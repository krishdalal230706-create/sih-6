import { describe, it } from 'node:test';
import assert from 'node:assert';
import { sanitizeEndpointEventsToPattern, sanitizeAccountAlertToPattern } from '../engine/privacyEngine.js';
import { correlateThreatPatterns } from '../engine/correlationEngine.js';
import { addLedgerBlock, verifyLedgerChain } from '../engine/dltLedger.js';
import { endpointDb } from '../db/endpointDb.js';
import { accountDetectionEngine } from '../engine/accountDetectionEngine.js';
import { ThreatPattern } from '../types.js';

describe('Module 8 Phase 7: Collaborative Threat Pattern Sharing & Early Warning Link', () => {
  it('Sanitizes endpoint telemetry: strips PII, hostnames, IPs and extracts behavior sequence', () => {
    const rawEvents = [
      { event_type: 'FAILED_LOGIN', details: 'Brute force login from 198.51.100.42 targeting alice@banka.com' },
      { event_type: 'FAILED_LOGIN', details: 'Repeated failed logon on ALICE-LAPTOP-W11' },
      { event_type: 'ANOMALOUS_GEO', details: 'Logon from Frankfurt (unusual geo)' },
      { event_type: 'PRIVILEGE_ESCALATION', details: 'Process demo_suspicious token elevated with SeDebugPrivilege' },
      { event_type: 'LARGE_DATA_TRANSFER', details: 'Egress 4.8 GB encrypted stream to external IP' }
    ];

    const result = sanitizeEndpointEventsToPattern(
      'DEV-BANK-01',
      'ALICE-LAPTOP-W11',
      'alice@banka.com',
      rawEvents,
      'org-1'
    );

    assert.ok(result.sanitizedPattern.threatPatternId.startsWith('TH-'));
    assert.ok(result.sanitizedPattern.patternHash);
    assert.strictEqual(result.maskedFields.length, 5);

    // Verify behavioral sequence extracted without PII
    const seq = result.sanitizedPattern.behaviorSequence;
    assert.ok(seq.includes('FAILED_LOGIN'));
    assert.ok(seq.includes('UNUSUAL_LOCATION'));
    assert.ok(seq.includes('PRIVILEGE_ESCALATION'));
    assert.ok(seq.includes('LARGE_DATA_TRANSFER'));

    // Verify no user email or internal IP in sanitized sequence
    const serializedSeq = JSON.stringify(seq);
    assert.strictEqual(serializedSeq.includes('alice@banka.com'), false);
    assert.strictEqual(serializedSeq.includes('198.51.100.42'), false);
    assert.strictEqual(serializedSeq.includes('ALICE-LAPTOP-W11'), false);
  });

  it('Correlates shared pattern against peer institutions and triggers early warning', () => {
    const testPattern: ThreatPattern = {
      id: 'tp-test-01',
      patternCode: 'TH-9021',
      originOrgId: 'org-1',
      originOrgName: 'Bank A',
      patternSequence: ['FAILED_LOGIN', 'NEW_DEVICE', 'UNUSUAL_LOCATION', 'PRIVILEGE_ESCALATION', 'LARGE_DATA_TRANSFER'],
      severity: 'CRITICAL',
      confidence: 96,
      status: 'Confirmed',
      hash: 'sha256-hash-test-pattern-9021',
      createdAt: new Date().toISOString(),
      isShared: true
    };

    // Peer institution (Hospital B) has near-identical sequence in progress
    const hospitalEvents = ['FAILED_LOGIN', 'NEW_DEVICE', 'UNUSUAL_LOCATION', 'PRIVILEGE_ESCALATION', 'LARGE_DATA_TRANSFER'];

    const correlation = correlateThreatPatterns(testPattern, 'org-2', 'Hospital B', hospitalEvents);

    assert.strictEqual(correlation.similarityPercentage, 100);
    assert.strictEqual(correlation.confidence, 'High');
    assert.strictEqual(correlation.earlyWarningTriggered, true);
    assert.match(correlation.warningMessage, /EARLY WARNING/);
  });

  it('Anchors shared threat pattern to DLT Trust Ledger and maintains ledger consensus', () => {
    const threatId = 'TH-9021';
    const reporterOrg = 'Bank A';
    const patternHash = 'pattern-hash-sha256-0000000000000000000000000000000000000001';

    const block = addLedgerBlock(threatId, reporterOrg, patternHash, ['Bank A', 'City Hospital', 'State University'], 'CONFIRMED');

    assert.ok(block.blockNumber >= 10000);
    assert.strictEqual(block.threatId, threatId);
    assert.strictEqual(block.reporterOrg, reporterOrg);

    const verification = verifyLedgerChain();
    assert.strictEqual(verification.isVerified, true, 'Ledger chain remains cryptographically intact after pattern anchor');
  });

  it('Sanitizes account attack alert: removes employee names, emails, user IDs, and client IPs', () => {
    const alert = {
      id: 'alt-usrbankalice',
      userId: 'usr-bank-alice',
      userEmail: 'alice@banka.com',
      userName: 'Alice Walker',
      orgId: 'org-1',
      severity: 'CRITICAL',
      confidence: 94,
      matchedRules: [
        'RULE-AUTH-01: Rapid Failed Logins (5 failed attempts in 60s)',
        'RULE-AUTH-02: Successful Login After Multiple Failures',
        'RULE-DEV-03: Unrecognized Device Hardware Fingerprint',
        'RULE-GEO-04: Anomalous Geographic Velocity (Frankfurt, DE)',
        'RULE-PRIV-05: Unauthorized Privilege Escalation Attempt',
        'RULE-DATA-06: High-Volume Sensitive Data Egress Anomaly (4.5 GB)'
      ],
      title: 'HOSTILE ACCOUNT COMPROMISE & ELEVATION DETECTED: ALICE WALKER',
      summary: 'Correlated 6 attack rules'
    };

    const result = sanitizeAccountAlertToPattern(alert);

    assert.ok(result.sanitizedPattern.threatPatternId.startsWith('TH-ACCT-'));
    assert.ok(result.sanitizedPattern.patternHash);
    assert.strictEqual(result.maskedFields.length, 5);

    const seq = result.sanitizedPattern.behaviorSequence;
    assert.ok(seq.includes('FAILED_LOGIN_STREAK'));
    assert.ok(seq.includes('POST_BRUTE_FORCE_SUCCESS'));
    assert.ok(seq.includes('UNRECOGNIZED_DEVICE'));
    assert.ok(seq.includes('ANOMALOUS_GEO_VELOCITY'));
    assert.ok(seq.includes('UNAUTHORIZED_PRIVILEGE_ELEVATION'));
    assert.ok(seq.includes('HIGH_VOLUME_DATA_EXFIL'));

    // Assert zero PII in serialized sequence
    const serialized = JSON.stringify(seq);
    assert.strictEqual(serialized.includes('Alice Walker'), false);
    assert.strictEqual(serialized.includes('alice@banka.com'), false);
    assert.strictEqual(serialized.includes('usr-bank-alice'), false);
    assert.strictEqual(serialized.includes('198.51.100.42'), false);
  });

  it('Executes Account Attack Demo sequence and ensures baseline reset gives reproducible identical results', () => {
    // Reset baseline first
    endpointDb.resetToBaseline();
    accountDetectionEngine.clearAllAlerts();

    // 1. Simulate attack on Alice
    const alert1 = accountDetectionEngine.simulateAccountAttack('usr-bank-alice');
    assert.strictEqual(alert1.id, 'alt-usrbankalice');
    assert.strictEqual(alert1.severity, 'CRITICAL');
    assert.ok(alert1.confidence >= 90);

    // 2. Admin fix: lock account & revoke sessions
    endpointDb.updateUserStatus('usr-bank-alice', 'locked');
    endpointDb.revokeAllUserSessions('usr-bank-alice');
    endpointDb.addAccountNotice('usr-bank-alice', 'org-1', 'ACCOUNT_LOCKED', 'Your account was locked by an administrator.');

    const userLocked = endpointDb.getUserById('usr-bank-alice');
    assert.strictEqual(userLocked?.status, 'locked');

    // 3. Remediate alert
    const remResult = accountDetectionEngine.remediateAlert(alert1.id, 'admin@banka.com');
    assert.ok(remResult);
    assert.strictEqual(remResult?.alert.status, 'Remediated');
    assert.strictEqual(remResult?.alert.accountRiskScore, 18);

    // 4. Reset baseline
    endpointDb.resetToBaseline();
    accountDetectionEngine.clearAllAlerts();

    // 5. Rerun attack - must give identical alert ID and scores
    const alert2 = accountDetectionEngine.simulateAccountAttack('usr-bank-alice');
    assert.strictEqual(alert2.id, alert1.id, 'Demo alert ID must be strictly identical across repeat runs');
    assert.strictEqual(alert2.confidence, alert1.confidence, 'Confidence must be identical across repeat runs');
    assert.strictEqual(alert2.accountRiskScore, alert1.accountRiskScore, 'Risk score must be identical across repeat runs');

    // Clean up
    endpointDb.resetToBaseline();
  });
});

