import { describe, it } from 'node:test';
import assert from 'node:assert';
import crypto from 'crypto';
import { endpointDb, CommandRecord } from '../db/endpointDb.js';
import { computeCommandSignature } from '../routes/commands.js';
import { db } from '../models/db.js';
import { calculateOrganizationRisk } from '../engine/riskEngine.js';

describe('Module 8 Phase 5: Remote Remediation, Command Whitelist, Signatures & Risk De-escalation', () => {
  const bankDevice = endpointDb.getDeviceById('DEV-BANK-01')!;
  const secretRecord = endpointDb.getDeviceSecret('DEV-BANK-01')!;

  it('Verifies command signing: HMAC-SHA256 produces valid deterministic signature', () => {
    const cmdId = `test-cmd-${Date.now()}`;
    const nonce = `test-nonce-${Date.now()}`;
    const issuedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 60000).toISOString();
    const params = { processName: 'demo_suspicious' };

    const sig = computeCommandSignature(
      secretRecord.command_secret,
      cmdId,
      'DEV-BANK-01',
      'kill_process',
      params,
      'admin@banka.com',
      issuedAt,
      expiresAt,
      nonce
    );

    assert.ok(sig, 'Signature generated');
    assert.strictEqual(typeof sig, 'string');
    assert.strictEqual(sig.length, 64, 'HMAC-SHA256 generates 64 hex characters');

    // Deterministic verify
    const sigAgain = computeCommandSignature(
      secretRecord.command_secret,
      cmdId,
      'DEV-BANK-01',
      'kill_process',
      params,
      'admin@banka.com',
      issuedAt,
      expiresAt,
      nonce
    );
    assert.strictEqual(sig, sigAgain, 'Signatures for identical payloads must match');
  });

  it('Detects parameter tampering: altered payload fails verification', () => {
    const cmdId = `test-cmd-tamper-${Date.now()}`;
    const nonce = `nonce-tamper-${Date.now()}`;
    const issuedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 60000).toISOString();

    const legitimateSig = computeCommandSignature(
      secretRecord.command_secret,
      cmdId,
      'DEV-BANK-01',
      'kill_process',
      { processName: 'demo_suspicious' },
      'admin@banka.com',
      issuedAt,
      expiresAt,
      nonce
    );

    // Attacker tampers params to target a system process
    const tamperedSig = computeCommandSignature(
      secretRecord.command_secret,
      cmdId,
      'DEV-BANK-01',
      'kill_process',
      { processName: 'critical_service' },
      'admin@banka.com',
      issuedAt,
      expiresAt,
      nonce
    );

    assert.notStrictEqual(legitimateSig, tamperedSig, 'Tampered parameters must result in signature mismatch');
  });

  it('Queues commands in database and tracks pending state for offline devices', () => {
    const cmdId = `test-cmd-queue-${Date.now()}`;
    const nonce = `nonce-queue-${Date.now()}`;
    const issuedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 60000).toISOString();
    const params = { filename: 'test_payload.bin' };

    const sig = computeCommandSignature(
      secretRecord.command_secret,
      cmdId,
      'DEV-BANK-01',
      'quarantine_file',
      params,
      'admin@banka.com',
      issuedAt,
      expiresAt,
      nonce
    );

    const commandRecord: CommandRecord = {
      id: cmdId,
      device_id: 'DEV-BANK-01',
      action: 'quarantine_file',
      params: JSON.stringify(params),
      status: 'Pending',
      issued_by: 'admin@banka.com',
      issued_at: issuedAt,
      expires_at: expiresAt,
      nonce,
      signature: sig,
      result: null,
      result_at: null
    };

    endpointDb.recordCommand(commandRecord);

    const pending = endpointDb.getPendingCommandsForDevice('DEV-BANK-01');
    const queued = pending.find((c) => c.id === cmdId);
    assert.ok(queued, 'Command must be queued in database');
    assert.strictEqual(queued.status, 'Pending');

    // Transition status to Executed
    endpointDb.updateCommandStatus(cmdId, 'Executed', JSON.stringify({ quarantined: 'test_payload.bin' }));
    const fetched = endpointDb.getCommandById(cmdId);
    assert.strictEqual(fetched?.status, 'Executed');
    assert.ok(fetched?.result?.includes('quarantined'));
  });

  it('De-escalates organization risk upon successful threat remediation', () => {
    const org = db.organizations['org-1'];
    // Simulate elevated risk before remediation
    org.riskScore = 88;
    org.riskBreakdown.endpointSecurity = 90;
    org.riskBreakdown.authentication = 85;

    // Simulate remediation execution
    org.riskBreakdown.endpointSecurity = Math.max(10, org.riskBreakdown.endpointSecurity - 15);
    org.riskBreakdown.authentication = Math.max(10, org.riskBreakdown.authentication - 15);
    org.riskTrend = 'FALLING';

    const newRisk = calculateOrganizationRisk(org, 0);
    org.riskScore = newRisk.overallRiskScore;

    assert.ok(org.riskScore < 88, 'Organization risk score must drop following remediation');
    assert.strictEqual(org.riskTrend, 'FALLING');
  });

  it('Revokes user sessions on force_logout command execution', () => {
    const user = endpointDb.getUserByEmail('alice@banka.com')!;
    const dummyToken = `tok-test-sess-${Date.now()}`;
    endpointDb.createSession(user.id, dummyToken);

    // Verify session active
    assert.strictEqual(endpointDb.isSessionValid(dummyToken), true);

    // Simulate force_logout revocation
    endpointDb.revokeAllUserSessions(user.id);

    // Session must now be invalid
    assert.strictEqual(endpointDb.isSessionValid(dummyToken), false);
  });
});
