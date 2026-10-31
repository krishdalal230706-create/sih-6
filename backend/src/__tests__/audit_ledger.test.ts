import { describe, it } from 'node:test';
import assert from 'node:assert';
import { endpointDb, computeAuditHash } from '../db/endpointDb.js';
import { addLedgerBlock, verifyLedgerChain } from '../engine/dltLedger.js';

describe('Module 8 Phase 6: Immutable Audit Hash-Chain & DLT Ledger Anchoring', () => {
  it('Enforces SHA-256 hash-chaining: every record includes prev_hash', () => {
    const actor = 'admin@banka.com';
    const orgId = 'org-1';
    const action = 'TEST_AUDIT_ACTION';
    const details = 'Test event for cryptographic hash chaining';

    const r1 = endpointDb.appendAudit(actor, orgId, action, details + ' 1');
    const r2 = endpointDb.appendAudit(actor, orgId, action, details + ' 2');

    assert.ok(r1.hash);
    assert.ok(r2.hash);
    assert.strictEqual(r2.prev_hash, r1.hash, 'Record 2 prev_hash must strictly point to Record 1 hash');

    // Manually verify computed hash matches formula
    const expectedHash2 = computeAuditHash(
      r2.id,
      r2.ts,
      r2.actor,
      r2.org_id,
      r2.device_id,
      r2.action,
      r2.details,
      r2.prev_hash
    );
    assert.strictEqual(r2.hash, expectedHash2, 'Stored record hash must match recomputed SHA-256 value');
  });

  it('Verifies clean audit chain integrity when untouched', () => {
    const result = endpointDb.verifyAuditChain();
    assert.strictEqual(result.isVerified, true, 'Untampered audit chain must verify cleanly');
    assert.strictEqual(result.brokenId, null);
    assert.ok(result.totalVerified > 0);
  });

  it('Detects adversarial modification: pinpoint-identifies tampered record ID', () => {
    const tamperRes = endpointDb.tamperAuditRecord();
    assert.ok(tamperRes.tamperedId);

    const verifyAfterTamper = endpointDb.verifyAuditChain();
    assert.strictEqual(verifyAfterTamper.isVerified, false, 'Tampered log must fail hash-chain verification');
    assert.strictEqual(verifyAfterTamper.brokenId, tamperRes.tamperedId, 'Verifier must catch exact broken record ID');
    assert.match(verifyAfterTamper.details, /Cryptographic tamper detected/);

    // Repair the record to restore clean state
    endpointDb.resetToBaseline();
    const verifyRestored = endpointDb.verifyAuditChain();
    assert.strictEqual(verifyRestored.isVerified, true, 'Chain must verify cleanly once restored');
  });

  it('Anchors audit root digest into DLT ledger and verifies block integrity', () => {
    const orgId = 'org-1';
    const auditLogs = endpointDb.getAuditLogs(orgId, 1);
    const latestHash = auditLogs[0].hash;
    const patternHash = `ROOT-SHA256-${latestHash.slice(0, 24)}`;
    const threatId = `AUDIT-CHECKPOINT-${Date.now()}`;

    const newBlock = addLedgerBlock(
      threatId,
      orgId,
      patternHash,
      [orgId, 'Hospital B', 'University C'],
      'CONFIRMED'
    );

    assert.ok(newBlock.blockNumber >= 10000);
    assert.strictEqual(newBlock.patternHash, patternHash);

    // Verify whole ledger chain
    const ledgerVerif = verifyLedgerChain();
    assert.strictEqual(ledgerVerif.isVerified, true, 'DLT ledger chain must verify cleanly with new anchor block');
  });

  it('Records all account protection actions with actor, timestamp, target user, action, and result in hash chain', () => {
    const admin = 'admin@banka.com';
    const orgId = 'org-1';
    const targetUser = 'alice@banka.com';

    const actions = [
      { action: 'USER_ACCOUNT_LOCKED', details: `Account ${targetUser} was locked by SOC administrator ${admin}. All active sessions revoked. Result: SUCCESS` },
      { action: 'USER_SESSIONS_REVOKED', details: `All active sessions revoked for ${targetUser} by administrator ${admin}. Result: SUCCESS` },
      { action: 'PASSWORD_RESET_FORCED', details: `Mandatory password reset required for ${targetUser} by administrator ${admin}. Result: SUCCESS` },
      { action: 'MFA_ENFORCED', details: `Multi-factor authentication (MFA) policy enforced for ${targetUser} by administrator ${admin}. Result: SUCCESS` },
      { action: 'PERIMETER_ENTITY_BLOCKED', details: `Perimeter access blocked for IP 198.51.100.42 for user ${targetUser} by ${admin}. Result: SUCCESS` },
      { action: 'PRIVILEGE_REVERTED', details: `Privileges reverted to STANDARD baseline for ${targetUser} by ${admin}. Result: SUCCESS` },
      { action: 'USER_ACCOUNT_UNLOCKED', details: `Account ${targetUser} unlocked and restored to active status by administrator ${admin}. Result: SUCCESS` }
    ];

    for (const item of actions) {
      const rec = endpointDb.appendAudit(admin, orgId, item.action, item.details);
      assert.ok(rec.hash);
      assert.strictEqual(rec.actor, admin);
      assert.strictEqual(rec.action, item.action);
      assert.ok(rec.details.includes(targetUser));
      assert.ok(rec.details.includes('Result: SUCCESS'));
    }

    const verification = endpointDb.verifyAuditChain();
    assert.strictEqual(verification.isVerified, true, 'Audit chain must verify after appending account security actions');
  });

  it('Anchors account incident digest into DLT ledger and sets status CONFIRMED when ledger is valid', () => {
    const orgId = 'org-1';
    const threatId = 'alt-usr-bank-alice';
    const patternHash = 'INCIDENT-SHA256-d7a8f3b2c1e0998877';

    const dltCheck = verifyLedgerChain();
    const expectedStatus = dltCheck.isVerified ? 'CONFIRMED' : 'PENDING';

    const newBlock = addLedgerBlock(
      threatId,
      orgId,
      patternHash,
      [orgId, 'Hospital B', 'University C'],
      expectedStatus
    );

    assert.ok(newBlock.blockNumber >= 10000);
    assert.strictEqual(newBlock.status, expectedStatus);
    assert.strictEqual(newBlock.threatId, threatId);

    const auditRec = endpointDb.appendAudit(
      'admin@banka.com',
      orgId,
      'DLT_INCIDENT_ANCHOR',
      `Incident ${threatId} digest anchored to DLT Ledger Block #${newBlock.blockNumber} (Digest: ${patternHash}, Status: ${expectedStatus}).`
    );

    assert.ok(auditRec.hash);
    const verification = endpointDb.verifyAuditChain();
    assert.strictEqual(verification.isVerified, true);
  });
});

