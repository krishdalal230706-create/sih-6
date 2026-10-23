import { VulnerabilityRecord, CyberGuardPriorityTier } from '../types/vulnerability.js';

export interface RiskCalculationInput {
  cvssScore: number;
  knownExploited: boolean;
  exploitAvailable: boolean;
  attackVector?: string;
  attackComplexity?: string;
  privilegesRequired?: string;
  userInteraction?: string;
  publishedDate?: string;
  modifiedDate?: string;
  source?: string;
}

export interface RiskCalculationResult {
  cyberGuardScore: number;
  cyberGuardPriority: CyberGuardPriorityTier;
  confidence: number;
  riskFactors: string[];
}

/**
 * Calculates a multi-signal CyberGuard Risk Prioritization score.
 * Unlike raw CVSS which is static and theoretical, CyberGuard Risk Prioritization
 * incorporates real-world weaponization, exploit availability, ease of exploitation,
 * and feed confidence.
 */
export function calculateCyberGuardRisk(input: RiskCalculationInput): RiskCalculationResult {
  const {
    cvssScore = 5.0,
    knownExploited = false,
    exploitAvailable = false,
    attackVector = 'NETWORK',
    attackComplexity = 'LOW',
    privilegesRequired = 'NONE',
    userInteraction = 'NONE',
    publishedDate,
    modifiedDate,
    source = 'NVD'
  } = input;

  const riskFactors: string[] = [];
  let score = 0;

  // 1. Base CVSS Contribution (0 to 45 points)
  const cvssBase = Math.min(45, (cvssScore / 10) * 45);
  score += cvssBase;

  // 2. Active Weaponization / CISA KEV Exploitation (+35 points)
  if (knownExploited) {
    score += 35;
    riskFactors.push('Confirmed Active Exploitation in the Wild (CISA KEV)');
  } else if (exploitAvailable) {
    score += 15;
    riskFactors.push('Public Exploit / Weaponized PoC Available');
  }

  // 3. Attack Vector
  const av = (attackVector || '').toUpperCase();
  if (av === 'NETWORK') {
    score += 10;
    riskFactors.push('Remotely Exploitable over Network');
  } else if (av === 'ADJACENT' || av === 'ADJACENT_NETWORK') {
    score += 6;
    riskFactors.push('Exploitable via Adjacent Network');
  } else if (av === 'LOCAL') {
    score += 3;
  } else if (av === 'PHYSICAL') {
    score += 1;
  }

  // 4. Attack Complexity
  const ac = (attackComplexity || '').toUpperCase();
  if (ac === 'LOW') {
    score += 5;
    riskFactors.push('Low Attack Complexity (Deterministic)');
  } else {
    score += 2;
  }

  // 5. Privileges Required
  const pr = (privilegesRequired || '').toUpperCase();
  if (pr === 'NONE') {
    score += 7;
    riskFactors.push('No Privileges Required (Unauthenticated)');
  } else if (pr === 'LOW') {
    score += 3;
  } else {
    score += 1;
  }

  // 6. User Interaction
  const ui = (userInteraction || '').toUpperCase();
  if (ui === 'NONE') {
    score += 4;
  } else if (ui === 'REQUIRED') {
    score += 1;
  }

  // 7. Recency Boost (Published / modified recently)
  const refDateStr = modifiedDate || publishedDate;
  if (refDateStr) {
    try {
      const date = new Date(refDateStr);
      const now = new Date();
      const diffDays = (now.getTime() - date.getTime()) / (1000 * 60 * 60 * 24);
      if (diffDays <= 30) {
        score += 5;
        riskFactors.push('Fresh Intelligence (< 30 days)');
      } else if (diffDays <= 90) {
        score += 3;
      }
    } catch {
      // ignore date parse errors
    }
  }

  // If known exploited, guarantee a minimum score of 85 (CRITICAL priority tier)
  if (knownExploited) {
    score = Math.max(86, score);
  }

  // Normalize final score to 0 - 100 range
  const cyberGuardScore = Math.min(100, Math.max(0, Math.round(score)));

  // Determine Priority Tier
  let cyberGuardPriority: CyberGuardPriorityTier = 'LOW';
  if (cyberGuardScore >= 85) {
    cyberGuardPriority = 'CRITICAL';
  } else if (cyberGuardScore >= 70) {
    cyberGuardPriority = 'HIGH';
  } else if (cyberGuardScore >= 45) {
    cyberGuardPriority = 'MEDIUM';
  } else {
    cyberGuardPriority = 'LOW';
  }

  // Source Confidence Metric
  let confidence = 85;
  const src = (source || '').toUpperCase();
  if (src.includes('CISA') && src.includes('NVD')) {
    confidence = 98;
  } else if (src.includes('CISA')) {
    confidence = 96;
  } else if (src.includes('NVD')) {
    confidence = 92;
  } else if (src.includes('GITHUB') || src.includes('OSV')) {
    confidence = 88;
  }

  return {
    cyberGuardScore,
    cyberGuardPriority,
    confidence,
    riskFactors
  };
}
