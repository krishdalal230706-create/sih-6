import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  calculateOrderAwareSimilarity,
  calculateSequenceSimilarity,
  correlateThreatPatterns,
  EVENT_SEVERITY_WEIGHTS
} from '../engine/correlationEngine.js';
import { ThreatPattern } from '../types.js';

describe('Order-Aware LCS Correlation & Pattern Matching', () => {
  const patternSeq = ['FAILED_LOGIN', 'NEW_DEVICE', 'UNUSUAL_LOCATION', 'PRIVILEGE_ESCALATION', 'LARGE_DATA_TRANSFER'];

  it('yields exactly 100% similarity for identical sequences', () => {
    const res = calculateOrderAwareSimilarity(patternSeq, [...patternSeq]);
    assert.strictEqual(res.similarity, 100);
    assert.strictEqual(res.matchingEvents.length, 5);
    assert.strictEqual(res.missingEvents.length, 0);
    assert.strictEqual(res.alignedBreakdown.every((b) => b.status === 'MATCHED'), true);
  });

  it('correctly degrades similarity when order is inverted', () => {
    // Reversing sequence breaks ordered subsequence alignment
    const reversedSeq = [...patternSeq].reverse();
    const res = calculateOrderAwareSimilarity(patternSeq, reversedSeq);
    assert.ok(res.similarity < 100, 'Reversed sequence similarity must be lower than ordered sequence');
    assert.ok(res.similarity > 0, 'Should still identify individual common token');
  });

  it('weights critical events higher than low events', () => {
    // Drop low/medium event (FAILED_LOGIN)
    const withoutFailedLogin = ['NEW_DEVICE', 'UNUSUAL_LOCATION', 'PRIVILEGE_ESCALATION', 'LARGE_DATA_TRANSFER'];
    const res1 = calculateOrderAwareSimilarity(patternSeq, withoutFailedLogin);

    // Drop critical event (LARGE_DATA_TRANSFER, weight 2.0)
    const withoutDataTransfer = ['FAILED_LOGIN', 'NEW_DEVICE', 'UNUSUAL_LOCATION', 'PRIVILEGE_ESCALATION'];
    const res2 = calculateOrderAwareSimilarity(patternSeq, withoutDataTransfer);

    // Losing a critical event should cause a lower similarity than losing a medium event
    assert.ok(
      res1.similarity > res2.similarity,
      `Expected similarity without medium event (${res1.similarity}%) to be higher than without critical event (${res2.similarity}%)`
    );
  });

  it('generates accurate aligned breakdowns with MATCHED, MISSING_IN_TARGET, and EXTRA', () => {
    const targetSeq = ['FAILED_LOGIN', 'NEW_DEVICE', 'PRIVILEGE_ESCALATION', 'UNEXPECTED_PROBE'];
    const res = calculateOrderAwareSimilarity(patternSeq, targetSeq);

    const statuses = res.alignedBreakdown.map((b) => b.status);
    assert.ok(statuses.includes('MATCHED'), 'Must have MATCHED events');
    assert.ok(statuses.includes('MISSING_IN_TARGET'), 'Must mark UNUSUAL_LOCATION or DATA_TRANSFER as MISSING');
    assert.ok(statuses.includes('EXTRA_IN_TARGET'), 'Must mark UNEXPECTED_PROBE as EXTRA');
  });

  it('triggers early warning when similarity exceeds 65%', () => {
    const mockPattern: ThreatPattern = {
      id: 'tp-1',
      patternCode: 'TH-7821',
      originOrgId: 'org-1',
      originOrgName: 'Demo Bank',
      patternSequence: patternSeq,
      severity: 'CRITICAL',
      confidence: 95,
      status: 'Confirmed',
      hash: 'abc1234567890abcdef',
      createdAt: '2026-09-04 10:00:00',
      isShared: true
    };

    const targetEventsHigh = ['FAILED_LOGIN', 'NEW_DEVICE', 'UNUSUAL_LOCATION', 'PRIVILEGE_ESCALATION', 'LARGE_DATA_TRANSFER'];
    const corrHigh = correlateThreatPatterns(mockPattern, 'org-2', 'City Hospital', targetEventsHigh);
    assert.strictEqual(corrHigh.earlyWarningTriggered, true);
    assert.ok(corrHigh.similarityPercentage >= 65);

    const targetEventsLow = ['FAILED_LOGIN', 'CLEARED_LOGS'];
    const corrLow = correlateThreatPatterns(mockPattern, 'org-5', 'Apex Energy', targetEventsLow);
    assert.strictEqual(corrLow.earlyWarningTriggered, false);
    assert.ok(corrLow.similarityPercentage < 65);
  });
});
