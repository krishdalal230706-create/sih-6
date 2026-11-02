import { Organization, RiskContributor } from '../types.js';
import { endpointDb, BankAssetRecord } from '../db/endpointDb.js';

export interface BankingCategoryScores {
  authentication: number;        // 15%
  coreBanking: number;           // 15%
  paymentGateway: number;        // 15%
  customerData: number;          // 10%
  networkSecurity: number;       // 10%
  endpointSecurity: number;      // 10%
  atmSecurity: number;           // 10%
  thirdParty: number;            // 5%
  vulnerabilityExposure: number; // 5%
  incidentHistory: number;       // 5%
}

export const BANKING_RISK_WEIGHTS = {
  authentication: 0.15,
  coreBanking: 0.15,
  paymentGateway: 0.15,
  customerData: 0.10,
  networkSecurity: 0.10,
  endpointSecurity: 0.10,
  atmSecurity: 0.10,
  thirdParty: 0.05,
  vulnerabilityExposure: 0.05,
  incidentHistory: 0.05
};

export interface HighestRiskAssetSummary {
  id: string;
  name: string;
  category: string;
  riskScore: number;
  securityStatus: string;
}

export interface ExplainableRiskDelta {
  factor: string;
  weight: string;
  score: number;
  weightedImpact: number;
  explanation: string;
}

export interface CalculatedRiskResult {
  overallRiskScore: number;
  riskTrend: 'RISING' | 'STABLE' | 'FALLING';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  categoryScores: {
    authentication: number;
    networkSecurity: number;
    dataSecurity: number;
    endpointSecurity: number;
    userRisk: number;
  };
  bankingCategoryScores: BankingCategoryScores;
  highestRiskAssets: HighestRiskAssetSummary[];
  recommendations: string[];
  explainableDeltas: ExplainableRiskDelta[];
  contributors: RiskContributor[];
  explanation: string[];
  formulaDetails: {
    authenticationWeight: string;
    networkWeight: string;
    dataWeight: string;
    vulnerabilitiesWeight: string;
    controlsWeight: string;
    incidentsWeight: string;
    [key: string]: string;
  };
}

export function calculateOrganizationRisk(
  org: Organization,
  activeIncidentsCount: number = 2,
  overrideAssets?: BankAssetRecord[]
): CalculatedRiskResult {
  // Retrieve bank assets if Demo Bank (org-1)
  const isDemoBank = org.id === 'org-1' || !org.id;
  let bankAssets: BankAssetRecord[] = overrideAssets || [];
  if (bankAssets.length === 0 && isDemoBank) {
    try {
      bankAssets = endpointDb.getBankAssets('org-1');
    } catch {
      bankAssets = [];
    }
  }

  // Derive scores for 10 Banking Categories:
  // 1. Authentication Security (15%)
  const authAsset = bankAssets.find((a) => a.id === 'asset-auth' || a.category === 'Authentication Server');
  const authScore = authAsset ? authAsset.risk_score : (org.riskBreakdown?.authentication ?? 25);

  // 2. Core Banking System Security (15%)
  const cbsAsset = bankAssets.find((a) => a.id === 'asset-cbs' || a.category === 'Core Banking');
  const cbsScore = cbsAsset ? cbsAsset.risk_score : 28;

  // 3. Payment Gateway Security (15%)
  const paymentAsset = bankAssets.find((a) => a.id === 'asset-payment' || a.category === 'Payment Gateway');
  const paymentScore = paymentAsset ? paymentAsset.risk_score : 85;

  // 4. Customer Data Protection (10%)
  const custDbAsset = bankAssets.find((a) => a.id === 'asset-custdb' || a.category === 'Customer Database');
  const custDbScore = custDbAsset ? custDbAsset.risk_score : (org.riskBreakdown?.dataSecurity ?? 35);

  // 5. Network Security (10%)
  const netAsset = bankAssets.find((a) => a.id === 'asset-network' || a.category === 'Internal Network');
  const netScore = netAsset ? netAsset.risk_score : (org.riskBreakdown?.networkSecurity ?? 30);

  // 6. Endpoint Security (10%)
  const endpointAsset = bankAssets.find((a) => a.id === 'asset-workstations' || a.category === 'Workstations & Endpoints');
  const endpointScore = endpointAsset ? endpointAsset.risk_score : (org.riskBreakdown?.endpointSecurity ?? 58);

  // 7. ATM Security (10%)
  const atmAsset = bankAssets.find((a) => a.id === 'asset-atm' || a.category === 'ATM Infrastructure');
  const atmScore = atmAsset ? atmAsset.risk_score : 40;

  // 8. Third-Party Risk (5%)
  const netbankAsset = bankAssets.find((a) => a.id === 'asset-netbank');
  const thirdPartyScore = netbankAsset ? Math.round((netbankAsset.risk_score * 0.6) + 15) : 35;

  // 9. Vulnerability Exposure (5%)
  const totalAssetVulns = bankAssets.reduce((sum, a) => sum + (a.associated_vulns_count || 0), 0);
  const vulnScore = Math.min(100, Math.max(15, (org.knownVulnerabilities || 0) * 3 + totalAssetVulns * 2.5));

  // 10. Incident History (5%)
  const incidentScore = Math.min(100, Math.max(10, activeIncidentsCount * 25));

  const bankingScores: BankingCategoryScores = {
    authentication: authScore,
    coreBanking: cbsScore,
    paymentGateway: paymentScore,
    customerData: custDbScore,
    networkSecurity: netScore,
    endpointSecurity: endpointScore,
    atmSecurity: atmScore,
    thirdParty: thirdPartyScore,
    vulnerabilityExposure: Math.round(vulnScore),
    incidentHistory: incidentScore
  };

  // Weighted calculation (Weights strictly sum to 1.00 / 100%)
  const weightedScore = Math.round(
    bankingScores.authentication * BANKING_RISK_WEIGHTS.authentication +
    bankingScores.coreBanking * BANKING_RISK_WEIGHTS.coreBanking +
    bankingScores.paymentGateway * BANKING_RISK_WEIGHTS.paymentGateway +
    bankingScores.customerData * BANKING_RISK_WEIGHTS.customerData +
    bankingScores.networkSecurity * BANKING_RISK_WEIGHTS.networkSecurity +
    bankingScores.endpointSecurity * BANKING_RISK_WEIGHTS.endpointSecurity +
    bankingScores.atmSecurity * BANKING_RISK_WEIGHTS.atmSecurity +
    bankingScores.thirdParty * BANKING_RISK_WEIGHTS.thirdParty +
    bankingScores.vulnerabilityExposure * BANKING_RISK_WEIGHTS.vulnerabilityExposure +
    bankingScores.incidentHistory * BANKING_RISK_WEIGHTS.incidentHistory
  );

  const overallRiskScore = Math.max(1, Math.min(100, weightedScore));

  let severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW';
  if (overallRiskScore >= 80) severity = 'CRITICAL';
  else if (overallRiskScore >= 65) severity = 'HIGH';
  else if (overallRiskScore >= 45) severity = 'MEDIUM';

  // Identify highest-risk banking assets
  const sortedAssets = [...bankAssets].sort((a, b) => b.risk_score - a.risk_score);
  const highestRiskAssets: HighestRiskAssetSummary[] = sortedAssets.slice(0, 5).map((a) => ({
    id: a.id,
    name: a.name,
    category: a.category,
    riskScore: a.risk_score,
    securityStatus: a.security_status
  }));

  // Explainable Factor Deltas
  const explainableDeltas: ExplainableRiskDelta[] = [
    {
      factor: 'Payment Gateway Security',
      weight: '15%',
      score: paymentScore,
      weightedImpact: Math.round(paymentScore * BANKING_RISK_WEIGHTS.paymentGateway * 10) / 10,
      explanation: paymentScore >= 70
        ? 'High vulnerability count and active fraud anomalies elevate gateway risk exposure.'
        : 'Payment gateway controls operating within normal variance.'
    },
    {
      factor: 'Branch Endpoint Security',
      weight: '10%',
      score: endpointScore,
      weightedImpact: Math.round(endpointScore * BANKING_RISK_WEIGHTS.endpointSecurity * 10) / 10,
      explanation: endpointScore >= 50
        ? 'Workstation fleet requires patch rollouts and strict removable media policies.'
        : 'Workstation EDR coverage is healthy across regional branches.'
    },
    {
      factor: 'ATM Switch & Network Security',
      weight: '10%',
      score: atmScore,
      weightedImpact: Math.round(atmScore * BANKING_RISK_WEIGHTS.atmSecurity * 10) / 10,
      explanation: 'ATM network switch communications operating under secure VPN and MACsec encryption.'
    },
    {
      factor: 'Core Banking System (CBS)',
      weight: '15%',
      score: cbsScore,
      weightedImpact: Math.round(cbsScore * BANKING_RISK_WEIGHTS.coreBanking * 10) / 10,
      explanation: 'Finacle CBS cluster is isolated within private banking enclave with HSM validation.'
    },
    {
      factor: 'Active Security Incidents',
      weight: '5%',
      score: incidentScore,
      weightedImpact: Math.round(incidentScore * BANKING_RISK_WEIGHTS.incidentHistory * 10) / 10,
      explanation: `${activeIncidentsCount} active investigation(s) currently open in Bank SOC.`
    }
  ];

  // Actionable Banking Recommendations
  const recommendations: string[] = [];
  if (paymentScore >= 60) {
    recommendations.push('Enforce immediate velocity rate limits on UPI gateway endpoints and rotate merchant API keys.');
  }
  if (bankingScores.thirdParty >= 30) {
    recommendations.push('Deploy Step-Up OTP & CAPTCHA on Internet Banking reverse proxy to mitigate credential stuffing.');
  }
  if (endpointScore >= 50) {
    recommendations.push('Audit removable media policies and enforce EDR compliance across all teller workstations.');
  }
  if (cbsScore >= 25) {
    recommendations.push('Review non-business hours database query authorizations on Finacle Core Banking cluster.');
  }
  if (recommendations.length === 0) {
    recommendations.push('Maintain routine periodic vulnerability scanning and automated ledger audit verification.');
  }

  // Key contributors for telemetry & UI widgets
  const contributors: RiskContributor[] = [
    {
      id: 'rc-bank-1',
      name: 'Payment Gateway Anomaly',
      points: Math.round(paymentScore * 0.3),
      category: 'Payment Systems',
      description: 'Micro-debit velocity burst detected on UPI gateway switch.'
    },
    {
      id: 'rc-bank-2',
      name: 'Internet Banking Credential Stuffing',
      points: Math.round(thirdPartyScore * 0.25),
      category: 'Digital Banking',
      description: 'Distributed proxy login failures targeting retail customer accounts.'
    },
    {
      id: 'rc-bank-3',
      name: 'Branch Teller Workstation Risks',
      points: Math.round(endpointScore * 0.2),
      category: 'Endpoints',
      description: 'Unpatched branch desktop endpoints with peripheral policy alerts.'
    },
    {
      id: 'rc-bank-4',
      name: 'Unpatched Infrastructure CVEs',
      points: Math.round(vulnScore * 0.15),
      category: 'Vulnerabilities',
      description: `${totalAssetVulns} unpatched CVEs identified across banking infrastructure.`
    }
  ];

  const explanation = [
    `Overall Bank Cyber Risk Score sits at ${overallRiskScore}/100 (${severity} severity).`,
    `Payment Gateway Security represents the largest contributing factor (+${Math.round(paymentScore * BANKING_RISK_WEIGHTS.paymentGateway)} pts to overall risk).`,
    `Core Banking System Finacle cluster remains well-defended (Score: ${cbsScore}/100).`,
    `Active Security Incidents (${activeIncidentsCount}) add +${Math.round(incidentScore * BANKING_RISK_WEIGHTS.incidentHistory)} pts to current risk exposure.`
  ];

  return {
    overallRiskScore,
    riskTrend: org.riskTrend || 'STABLE',
    severity,
    // Backward-compatible categoryScores
    categoryScores: {
      authentication: bankingScores.authentication,
      networkSecurity: bankingScores.networkSecurity,
      dataSecurity: bankingScores.customerData,
      endpointSecurity: bankingScores.endpointSecurity,
      userRisk: bankingScores.thirdParty
    },
    bankingCategoryScores: bankingScores,
    highestRiskAssets,
    recommendations,
    explainableDeltas,
    contributors,
    explanation,
    formulaDetails: {
      authenticationWeight: '15% (Weight: 0.15)',
      coreBankingWeight: '15% (Weight: 0.15)',
      paymentGatewayWeight: '15% (Weight: 0.15)',
      customerDataWeight: '10% (Weight: 0.10)',
      networkWeight: '10% (Weight: 0.10)',
      endpointWeight: '10% (Weight: 0.10)',
      atmSecurityWeight: '10% (Weight: 0.10)',
      thirdPartyWeight: '5% (Weight: 0.05)',
      vulnerabilitiesWeight: '5% (Weight: 0.05)',
      incidentsWeight: '5% (Weight: 0.05)',
      controlsWeight: '10% (Weight: 0.10)',
      dataWeight: '10% (Weight: 0.10)'
    }
  };
}
