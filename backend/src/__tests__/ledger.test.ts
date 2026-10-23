import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  computeBlockHash,
  verifyLedgerChain,
  verifyLedgerRecordIntegrity,
  tamperLedgerRecord,
  restoreLedgerBaseline,
  addLedgerBlock,
  advanceBlockValidation
} from '../engine/dltLedger.js';
import { calculateOrganizationRisk } from '../engine/riskEngine.js';
import { calculateSequenceSimilarity } from '../engine/correlationEngine.js';

describe('DLT Ledger Hashing & Cryptographic Verification', () => {
  it('computes deterministic SHA-256 block hash', () => {
    const hash1 = computeBlockHash(
      10001,
      'TH-7821',
      'Demo Bank',
      'a8f3b29c91d4e5f670123456789abcdef0123456789abcdef0123456789ab2bd',
      ['Demo Bank', 'City Hospital'],
      '2026-09-04 10:00:00',
      '0000000000000000000000000000000000000000000000000000000000000000'
    );
    const hash2 = computeBlockHash(
      10001,
      'TH-7821',
      'Demo Bank',
      'a8f3b29c91d4e5f670123456789abcdef0123456789abcdef0123456789ab2bd',
      ['Demo Bank', 'City Hospital'],
      '2026-09-04 10:00:00',
      '0000000000000000000000000000000000000000000000000000000000000000'
    );
    assert.strictEqual(hash1, hash2);
    assert.strictEqual(hash1.length, 64);
  });

  it('verifies baseline chain integrity cleanly', () => {
    restoreLedgerBaseline();
    const result = verifyLedgerChain();
    assert.strictEqual(result.isVerified, true);
    assert.strictEqual(result.brokenBlockNumber, null);
    assert.strictEqual(result.errorType, 'NONE');
    assert.ok(result.totalBlocksVerified >= 3);
  });

  it('detects tampering and flags the exact broken block', () => {
    restoreLedgerBaseline();
    // Tamper Block 10420
    const tamperRes = tamperLedgerRecord(10420, 'TH-MALICIOUS-ALTERED-999');
    assert.strictEqual(tamperRes.success, true);

    // Verify chain should now fail and identify block 10420
    const result = verifyLedgerChain();
    assert.strictEqual(result.isVerified, false);
    assert.strictEqual(result.brokenBlockNumber, 10420);

    // Individual verification should also flag tampering
    const singleVerify = verifyLedgerRecordIntegrity(10420);
    assert.strictEqual(singleVerify.isVerified, false);
    assert.strictEqual(singleVerify.recordModified, true);

    // Downstream block 10421 should also reflect broken linkage
    const downstreamVerify = verifyLedgerRecordIntegrity(10421);
    assert.strictEqual(downstreamVerify.isVerified, false);

    // Restore baseline
    restoreLedgerBaseline();
    const restored = verifyLedgerChain();
    assert.strictEqual(restored.isVerified, true);
  });

  it('progresses validator workflow from Reported through Quorum to Confirmed', () => {
    restoreLedgerBaseline();
    const newBlock = addLedgerBlock('TH-UNIT-TEST', 'Demo Bank', 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789', ['Demo Bank']);
    assert.strictEqual(newBlock.validators.length, 1);
    assert.strictEqual(newBlock.status, 'REPORTED');

    // Add 2nd validator -> Verified by 1
    const v2 = advanceBlockValidation(newBlock.blockNumber, 'City Hospital');
    assert.ok(v2);
    assert.strictEqual(v2.status, 'Verified by 1');

    // Add 3rd validator -> Verified by 3
    const v3 = advanceBlockValidation(newBlock.blockNumber, 'State University');
    assert.ok(v3);
    assert.strictEqual(v3.status, 'Verified by 3');

    // Add 4th validator -> CONFIRMED
    const v4 = advanceBlockValidation(newBlock.blockNumber, 'FinTech Corp');
    assert.ok(v4);
    assert.strictEqual(v4.status, 'CONFIRMED');

    // Chain remains valid
    const chainCheck = verifyLedgerChain();
    assert.strictEqual(chainCheck.isVerified, true);

    // Cleanup
    restoreLedgerBaseline();
  });
});

describe('Cyber Risk Scoring Engine', () => {
  it('calculates bounded risk score within 1-100 and correct severity', () => {
    const mockOrg: any = {
      id: 'org-1',
      name: 'Test Org',
      riskBreakdown: {
        authentication: 90,
        networkSecurity: 80,
        dataSecurity: 85,
        endpointSecurity: 70,
        userRisk: 60
      },
      knownVulnerabilities: 10,
      securityControls: ['Firewall', 'Antivirus'],
      dataSensitivity: 'CRITICAL',
      riskTrend: 'RISING'
    };

    const result = calculateOrganizationRisk(mockOrg, 2);
    assert.ok(result.overallRiskScore >= 1 && result.overallRiskScore <= 100);
    assert.ok(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(result.severity));
    assert.ok(result.contributors.length > 0);
  });
});

describe('Correlation Engine Sequence Matching', () => {
  it('returns valid percentage for sequence comparison', () => {
    const seqA = ['FAILED_LOGIN', 'NEW_DEVICE', 'PRIVILEGE_ESCALATION'];
    const seqB = ['FAILED_LOGIN', 'NEW_DEVICE', 'PRIVILEGE_ESCALATION'];
    const similarity = calculateSequenceSimilarity(seqA, seqB);
    assert.ok(similarity > 0 && similarity <= 100);
  });
});
