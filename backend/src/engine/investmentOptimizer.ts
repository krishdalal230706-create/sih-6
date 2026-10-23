import { vulnerabilityDb } from '../db/vulnerabilityDb.js';
import { VulnerabilityRecord } from '../types/vulnerability.js';

export interface OptimizationOptions {
  budget?: number;
  minCvss?: number;
  knownExploitedOnly?: boolean;
}

export interface InvestmentRecommendation {
  id: string;
  cveId: string;
  title: string;
  severity: string;
  cvssScore: number;
  cyberGuardPriority: string;
  cyberGuardScore: number;
  affectedVendor: string;
  affectedProduct: string;
  knownExploited: boolean;
  exploitAvailable: boolean;
  estimatedCost: number;
  costLabel: string;
  isCostEstimated: boolean;
  expectedRiskReduction: number;
  efficiencyScore: number; // Risk points per ₹100,000
  priorityRank: number;
  selectionStatus: 'SELECTED' | 'OUTSIDE_BUDGET';
  justificationReason: string;
}

export interface OptimizationResult {
  budget: number;
  totalInvested: number;
  totalRiskReduced: number;
  remainingBudget: number;
  selectedCount: number;
  totalEvaluated: number;
  recommendations: InvestmentRecommendation[];
  chartData: {
    step: number;
    allocatedBudget: number;
    cumulativeRiskReduction: number;
    cveId: string;
  }[];
  explanation: string;
}

/**
 * Calculates estimated remediation cost based on severity and attack complexity.
 * Explicitly marks cost as estimated when not present in raw vendor advisory.
 */
function estimateRemediationCost(vuln: VulnerabilityRecord): { cost: number; label: string; isEstimated: boolean } {
  // If remediation text contains explicit cost estimate, parse it
  if (vuln.remediation && vuln.remediation.includes('₹')) {
    const match = vuln.remediation.match(/₹\s*([\d,]+)/);
    if (match) {
      const parsed = parseInt(match[1].replace(/,/g, ''), 10);
      if (!isNaN(parsed) && parsed > 0) {
        return { cost: parsed, label: `₹${parsed.toLocaleString('en-IN')}`, isEstimated: false };
      }
    }
  }

  // Configurable transparent cost estimate based on severity & complexity
  let baseCost = 35000;
  if (vuln.severity === 'CRITICAL') baseCost = 150000;
  else if (vuln.severity === 'HIGH') baseCost = 85000;
  else if (vuln.severity === 'MEDIUM') baseCost = 35000;
  else baseCost = 15000;

  // Adjust for known weaponized exploitation
  if (vuln.knownExploited) {
    baseCost += 25000;
  }

  return {
    cost: baseCost,
    label: `₹${baseCost.toLocaleString('en-IN')} (Estimated based on ${vuln.severity} severity)`,
    isEstimated: true
  };
}

/**
 * Computes explainable risk reduction points (0 - 100) achieved by remediating this vulnerability.
 */
function calculateExpectedRiskReduction(vuln: VulnerabilityRecord): { riskPoints: number; reason: string } {
  let points = vuln.cvssScore * 9.5; // Base CVSS weight
  let multiplier = 1.0;
  const reasons: string[] = [];

  if (vuln.knownExploited) {
    multiplier += 0.45; // High priority boost for actively weaponized KEVs
    reasons.push('Actively exploited in the wild (CISA KEV cataloged)');
  } else if (vuln.exploitAvailable) {
    multiplier += 0.25;
    reasons.push('Public exploit code is available');
  }

  if (vuln.attackVector === 'NETWORK') {
    multiplier += 0.15;
    reasons.push('Remotely exploitable over network');
  }

  if (vuln.cyberGuardScore >= 85) {
    reasons.push('High CyberGuard priority impact score');
  }

  const finalPoints = Math.min(99, Math.round(points * multiplier));
  const primaryReason = reasons.length > 0
    ? reasons.join('. ') + '.'
    : `Remediates ${vuln.severity} severity exposure on ${vuln.affectedProduct}.`;

  return { riskPoints: finalPoints, reason: primaryReason };
}

/**
 * Investment Optimization Engine:
 * Given a user-provided budget, performs greedy knapsack allocation prioritizing highest ROI (Risk Reduction per Cost) & Weaponized KEVs.
 */
export async function optimizeCyberInvestment(options: OptimizationOptions = {}): Promise<OptimizationResult> {
  const budget = Math.max(0, Number(options.budget) ?? 1000000);

  // 1. Fetch real vulnerabilities stored in MySQL database
  const queryResult = await vulnerabilityDb.getVulnerabilities({
    limit: 200,
    minCvss: options.minCvss,
    knownExploited: options.knownExploitedOnly ? true : undefined,
    sortBy: 'cyberGuardScore',
    sortOrder: 'desc'
  });

  const rawVulns = queryResult.data || [];

  if (rawVulns.length === 0) {
    return {
      budget,
      totalInvested: 0,
      totalRiskReduced: 0,
      remainingBudget: budget,
      selectedCount: 0,
      totalEvaluated: 0,
      recommendations: [],
      chartData: [],
      explanation: 'No vulnerabilities match the current filter criteria.'
    };
  }

  // 2. Map and compute ROI metrics for each real vulnerability
  const items = rawVulns.map((vuln) => {
    const { cost, label, isEstimated } = estimateRemediationCost(vuln);
    const { riskPoints, reason } = calculateExpectedRiskReduction(vuln);
    const efficiency = cost > 0 ? (riskPoints / cost) * 100000 : 0;

    return {
      vuln,
      cost,
      label,
      isEstimated,
      riskPoints,
      reason,
      efficiency
    };
  });

  // 3. Sort by priority: Known Exploited first, then highest efficiency (Risk Points per Cost), then highest CVSS
  items.sort((a, b) => {
    if (a.vuln.knownExploited && !b.vuln.knownExploited) return -1;
    if (!a.vuln.knownExploited && b.vuln.knownExploited) return 1;
    if (b.efficiency !== a.efficiency) return b.efficiency - a.efficiency;
    return b.vuln.cvssScore - a.vuln.cvssScore;
  });

  // 4. Greedy Knapsack allocation based on budget
  let currentBudget = budget;
  let totalInvested = 0;
  let totalRiskReduced = 0;
  let selectedCount = 0;

  const recommendations: InvestmentRecommendation[] = [];
  const chartData: OptimizationResult['chartData'] = [
    { step: 0, allocatedBudget: 0, cumulativeRiskReduction: 0, cveId: 'START' }
  ];

  items.forEach((item, index) => {
    const isSelected = item.cost <= currentBudget && currentBudget > 0;

    if (isSelected) {
      currentBudget -= item.cost;
      totalInvested += item.cost;
      totalRiskReduced += item.riskPoints;
      selectedCount++;

      chartData.push({
        step: selectedCount,
        allocatedBudget: totalInvested,
        cumulativeRiskReduction: totalRiskReduced,
        cveId: item.vuln.cveId
      });
    }

    recommendations.push({
      id: item.vuln.id,
      cveId: item.vuln.cveId,
      title: item.vuln.title,
      severity: item.vuln.severity,
      cvssScore: item.vuln.cvssScore,
      cyberGuardPriority: item.vuln.cyberGuardPriority,
      cyberGuardScore: item.vuln.cyberGuardScore,
      affectedVendor: item.vuln.affectedVendor,
      affectedProduct: item.vuln.affectedProduct,
      knownExploited: item.vuln.knownExploited,
      exploitAvailable: item.vuln.exploitAvailable,
      estimatedCost: item.cost,
      costLabel: item.label,
      isCostEstimated: item.isEstimated,
      expectedRiskReduction: item.riskPoints,
      efficiencyScore: Math.round(item.efficiency * 10) / 10,
      priorityRank: index + 1,
      selectionStatus: isSelected ? 'SELECTED' : 'OUTSIDE_BUDGET',
      justificationReason: item.reason
    });
  });

  const explanation = selectedCount > 0
    ? `Allocated ₹${totalInvested.toLocaleString('en-IN')} across ${selectedCount} top-priority security remediations, achieving a total expected risk reduction of +${totalRiskReduced} risk points.`
    : `Budget of ₹${budget.toLocaleString('en-IN')} is insufficient for the top-priority remediations. Consider increasing budget allocation.`;

  return {
    budget,
    totalInvested,
    totalRiskReduced,
    remainingBudget: currentBudget,
    selectedCount,
    totalEvaluated: items.length,
    recommendations,
    chartData,
    explanation
  };
}
