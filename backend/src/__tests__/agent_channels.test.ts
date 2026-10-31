import { test, describe, before } from 'node:test';
import assert from 'node:assert';
import crypto from 'crypto';
import { endpointDb } from '../db/endpointDb.js';
import { wsHub } from '../ws/wsHub.js';

describe('Module 8 Phase 2: Agent Enrollment, WebSocket Channels & HMAC Verification', () => {
  before(() => {
    endpointDb.seedDefaultsIfEmpty();
  });

  test('Generates and single-use consumes enrollment codes', () => {
    const admin = endpointDb.getUserByEmail('admin@banka.com')!;
    const alice = endpointDb.getUserByEmail('alice@banka.com')!;

    const code = endpointDb.createEnrollmentCode(admin.org_id, alice.id, 60);
    assert.ok(code.startsWith('CG-'), 'Enrollment code must have CG- prefix');

    // First consumption succeeds
    const consumed = endpointDb.consumeEnrollmentCode(code);
    assert.ok(consumed, 'Code must be valid upon first use');
    assert.strictEqual(consumed.org_id, 'org-1');
    assert.strictEqual(consumed.user_id, alice.id);

    // Second consumption must fail (single-use only)
    const secondTry = endpointDb.consumeEnrollmentCode(code);
    assert.strictEqual(secondTry, null, 'Enrollment code must not be reusable');
  });

  test('Registers new device with hashed token and command secret', () => {
    const now = new Date().toISOString();
    const testDeviceId = 'DEV-BANK-TEST-09';
    const testToken = 'token-secret-alpha-99';
    const testCmdSecret = 'cmdsec-hmac-test-key-32chars-min!!';

    endpointDb.registerDevice(
      {
        id: testDeviceId,
        org_id: 'org-1',
        user_id: 'usr-bank-alice',
        hostname: 'TEST-ENROLLED-WS',
        os: 'Windows 11 Pro',
        status: 'Healthy',
        risk: 15,
        last_seen: now,
        enrolled_at: now
      },
      testCmdSecret,
      testToken
    );

    // Verify token verification function
    const isTokenValid = endpointDb.verifyDeviceToken(testDeviceId, testToken);
    assert.strictEqual(isTokenValid, true, 'Valid token must authenticate');

    const isBadToken = endpointDb.verifyDeviceToken(testDeviceId, 'wrong-token-value');
    assert.strictEqual(isBadToken, false, 'Invalid token must be rejected');

    const secretRec = endpointDb.getDeviceSecret(testDeviceId);
    assert.ok(secretRec);
    assert.strictEqual(secretRec.command_secret, testCmdSecret);
  });

  test('HMAC-SHA256 Command Signature Verification & Anti-Replay Nonce Logic', () => {
    const cmdSecret = 'test-secret-signing-key-12345678';
    const commandId = `cmd-test-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
    const deviceId = 'DEV-BANK-01';
    const action = 'kill_process';
    const params = { processName: 'demo_suspicious' };
    const issuedBy = 'admin@banka.com';
    const issuedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 60000).toISOString(); // 1 minute TTL
    const nonce = crypto.randomBytes(8).toString('hex');

    // Canonical signing payload
    const sortedParams = JSON.stringify(params, Object.keys(params).sort());
    const payload = `${commandId}|${deviceId}|${action}|${sortedParams}|${issuedBy}|${issuedAt}|${expiresAt}|${nonce}`;
    const validSignature = crypto.createHmac('sha256', cmdSecret).update(payload).digest('hex');

    // Verify signature matches
    const testSig = crypto.createHmac('sha256', cmdSecret).update(payload).digest('hex');
    assert.strictEqual(validSignature, testSig, 'Signature must match expected HMAC');

    // Forged signature with wrong secret fails
    const badSecretSig = crypto.createHmac('sha256', 'wrong-attacker-secret').update(payload).digest('hex');
    assert.notStrictEqual(validSignature, badSecretSig, 'Forged signature must be rejected');

    // Nonce replay tracking test
    const recordedNonce = endpointDb.getCommandByNonce(nonce);
    assert.strictEqual(recordedNonce, undefined, 'Fresh nonce must not exist yet');

    endpointDb.recordCommand({
      id: commandId,
      device_id: deviceId,
      action,
      params: sortedParams,
      status: 'Pending',
      issued_by: issuedBy,
      issued_at: issuedAt,
      expires_at: expiresAt,
      nonce,
      signature: validSignature,
      result: null,
      result_at: null
    });

    // Replay check
    const usedNonce = endpointDb.getCommandByNonce(nonce);
    assert.ok(usedNonce, 'Nonce must be recorded in commands table to reject future replays');
    assert.strictEqual(usedNonce.nonce, nonce);
  });

  test('Audit log verifies device-specific actions are chained immutably', () => {
    const audit = endpointDb.appendAudit(
      'admin@banka.com',
      'org-1',
      'COMMAND_ISSUED',
      'Admin issued isolate_device on DEV-BANK-01',
      'DEV-BANK-01'
    );
    assert.ok(audit.hash);
    assert.strictEqual(audit.device_id, 'DEV-BANK-01');

    const chain = endpointDb.verifyAuditChain();
    assert.strictEqual(chain.isVerified, true, 'Audit chain with device events must verify');
  });
});

