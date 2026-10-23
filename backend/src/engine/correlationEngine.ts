import { ThreatPattern, CorrelationResult, AlignedEventBreakdown } from '../types.js';

/**
 * Event severity definitions and analytical weights for correlation matching.
 * Critical events carry higher weight in calculating sequence similarity.
 */
export const EVENT_SEVERITY_WEIGHTS: Record<string, { severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'; weight: number }> = {
  PRIVILEGE_ESCALATION: { severity: 'CRITICAL', weight: 2.0 },
  LARGE_DATA_TRANSFER: { severity: 'CRITICAL', weight: 2.0 },
  DATA_EXFILTRATION: { severity: 'CRITICAL', weight: 2.0 },
  RANSOMWARE_STAGING: { severity: 'CRITICAL', weight: 2.0 },
  MALWARE_EXECUTION: { severity: 'CRITICAL', weight: 1.8 },
  NEW_DEVICE: { severity: 'HIGH', weight: 1.4 },
  UNUSUAL_LOCATION: { severity: 'HIGH', weight: 1.4 },
  SESSION_HIJACK: { severity: 'HIGH', weight: 1.5 },
  CREDENTIAL_THEFT: { severity: 'HIGH', weight: 1.5 },
  FAILED_LOGIN: { severity: 'MEDIUM', weight: 1.0 },
  SUCCESSFUL_LOGIN: { severity: 'LOW', weight: 0.8 },
  DATA_ACCESS: { severity: 'MEDIUM', weight: 1.0 },
  CLEARED_LOGS: { severity: 'HIGH', weight: 1.5 },
  UNUSUAL_ACCESS: { severity: 'MEDIUM', weight: 1.2 }
};

export function getEventMetadata(event: string): { severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'; weight: number } {
  return EVENT_SEVERITY_WEIGHTS[event] || { severity: 'MEDIUM', weight: 1.0 };
}

/**
 * Calculates order-aware sequence similarity using weighted Longest Common Subsequence (LCS).
 * Returns exact matching events, missing events, aligned step breakdown, and normalized 0-100% similarity.
 * Eliminates artificial caps and arbitrary bonuses.
 */
export function calculateOrderAwareSimilarity(
  seqA: string[],
  seqB: string[]
): {
  similarity: number;
  matchingEvents: string[];
  missingEvents: string[];
  alignedBreakdown: AlignedEventBreakdown[];
} {
  if (!seqA.length && !seqB.length) {
    return { similarity: 100, matchingEvents: [], missingEvents: [], alignedBreakdown: [] };
  }
  if (!seqA.length || !seqB.length) {
    return {
      similarity: 0,
      matchingEvents: [],
      missingEvents: [...seqA],
      alignedBreakdown: seqA.map((e) => ({
        eventA: e,
        eventB: null,
        status: 'MISSING_IN_TARGET',
        severity: getEventMetadata(e).severity,
        weight: getEventMetadata(e).weight
      }))
    };
  }

  const m = seqA.length;
  const n = seqB.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 1; i <= m; i++) {
    const w = getEventMetadata(seqA[i - 1]).weight;
    for (let j = 1; j <= n; j++) {
      if (seqA[i - 1] === seqB[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1] + w;
      } else {
        dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
  }

  // Backtrack to extract aligned sequence
  let i = m;
  let j = n;
  const rawAlignment: AlignedEventBreakdown[] = [];
  const matchingEvents: string[] = [];

  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && seqA[i - 1] === seqB[j - 1]) {
      const e = seqA[i - 1];
      const meta = getEventMetadata(e);
      rawAlignment.unshift({
        eventA: e,
        eventB: e,
        status: 'MATCHED',
        severity: meta.severity,
        weight: meta.weight
      });
      matchingEvents.unshift(e);
      i--;
      j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      const e = seqB[j - 1];
      const meta = getEventMetadata(e);
      rawAlignment.unshift({
        eventA: null,
        eventB: e,
        status: 'EXTRA_IN_TARGET',
        severity: meta.severity,
        weight: meta.weight
      });
      j--;
    } else {
      const e = seqA[i - 1];
      const meta = getEventMetadata(e);
      rawAlignment.unshift({
        eventA: e,
        eventB: null,
        status: 'MISSING_IN_TARGET',
        severity: meta.severity,
        weight: meta.weight
      });
      i--;
    }
  }

  const matchingSet = new Set(matchingEvents);
  const missingEvents = seqA.filter((e) => !matchingSet.has(e));

  const totalWeightA = seqA.reduce((sum, e) => sum + getEventMetadata(e).weight, 0);
  const totalWeightB = seqB.reduce((sum, e) => sum + getEventMetadata(e).weight, 0);
  const maxWeight = Math.max(totalWeightA, totalWeightB);

  const lcsWeight = dp[m][n];
  const similarity = maxWeight > 0 ? Math.round((lcsWeight / maxWeight) * 100) : 0;

  return {
    similarity,
    matchingEvents,
    missingEvents,
    alignedBreakdown: rawAlignment
  };
}

/**
 * Backward compatible function wrapper for sequence similarity
 */
export function calculateSequenceSimilarity(seqA: string[], seqB: string[]): number {
  return calculateOrderAwareSimilarity(seqA, seqB).similarity;
}

export function correlateThreatPatterns(
  sourcePattern: ThreatPattern,
  targetOrgId: string,
  targetOrgName: string,
  targetOrgEvents: string[]
): CorrelationResult {
  const result = calculateOrderAwareSimilarity(sourcePattern.patternSequence, targetOrgEvents);
  const similarity = result.similarity;

  let confidence: 'High' | 'Medium' | 'Low' = 'Low';
  if (similarity >= 80) confidence = 'High';
  else if (similarity >= 60) confidence = 'Medium';

  const earlyWarningTriggered = similarity >= 65;

  return {
    targetOrgId,
    targetOrgName,
    matchedThreatCode: sourcePattern.patternCode,
    similarityPercentage: similarity,
    confidence,
    earlyWarningTriggered,
    warningMessage: earlyWarningTriggered
      ? `🚨 EARLY WARNING: Similar adversary attack behavior (${similarity}% ordered sequence match) detected in ${targetOrgName} matching threat pattern ${sourcePattern.patternCode} reported by ${sourcePattern.originOrgName}.`
      : `ℹ️ NORMAL POSTURE: Baseline sequence match (${similarity}%) below early warning threshold in ${targetOrgName}.`,
    sequenceComparison: {
      patternA: sourcePattern.patternSequence,
      patternB: targetOrgEvents,
      matchingEvents: result.matchingEvents,
      missingEvents: result.missingEvents,
      alignedBreakdown: result.alignedBreakdown
    }
  };
}
