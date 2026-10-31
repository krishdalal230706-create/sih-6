import { describe, it } from 'node:test';
import assert from 'node:assert';
import { CommandExecutor, computeCommandSignature } from '../commandExecutor.js';
import { SignedCommand } from '../types.js';

describe('Agent Command Executor & Whitelist Enforcement', () => {
  const testSecret = 'secret-cmd-test-key-32characters-minimum!';
  const executor = new CommandExecutor(testSecret);

  it('Verifies valid HMAC-SHA256 signature and executes whitelisted command', async () => {
    const cmdId = `agent-cmd-${Date.now()}`;
    const nonce = `agent-nonce-${Date.now()}`;
    const issuedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 60000).toISOString();
    const params = {};

    const sig = computeCommandSignature(
      testSecret,
      cmdId,
      'DEV-TEST-01',
      'isolate_device',
      params,
      'admin@banka.com',
      issuedAt,
      expiresAt,
      nonce
    );

    const cmd: SignedCommand = {
      id: cmdId,
      deviceId: 'DEV-TEST-01',
      action: 'isolate_device',
      params,
      issuedBy: 'admin@banka.com',
      issuedAt,
      expiresAt,
      nonce,
      signature: sig
    };

    const res = await executor.executeCommand(cmd);
    assert.strictEqual(res.status, 'Executed');
    assert.strictEqual(executor.getIsIsolated(), true);
  });

  it('Rejects replay attacks when same nonce is submitted', async () => {
    const cmdId1 = `agent-cmd-orig-${Date.now()}`;
    const sharedNonce = `fixed-agent-nonce-${Date.now()}`;
    const issuedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 60000).toISOString();
    const params = {};

    const sig1 = computeCommandSignature(
      testSecret,
      cmdId1,
      'DEV-TEST-01',
      'release_isolation',
      params,
      'admin@banka.com',
      issuedAt,
      expiresAt,
      sharedNonce
    );

    const firstRun = await executor.executeCommand({
      id: cmdId1,
      deviceId: 'DEV-TEST-01',
      action: 'release_isolation',
      params,
      issuedBy: 'admin@banka.com',
      issuedAt,
      expiresAt,
      nonce: sharedNonce,
      signature: sig1
    });

    assert.strictEqual(firstRun.status, 'Executed');
    assert.strictEqual(executor.getIsIsolated(), false);

    // Replay attempt with same nonce
    const cmdId2 = `agent-cmd-replay-${Date.now()}`;
    const sig2 = computeCommandSignature(
      testSecret,
      cmdId2,
      'DEV-TEST-01',
      'release_isolation',
      params,
      'admin@banka.com',
      issuedAt,
      expiresAt,
      sharedNonce
    );

    const replayRun = await executor.executeCommand({
      id: cmdId2,
      deviceId: 'DEV-TEST-01',
      action: 'release_isolation',
      params,
      issuedBy: 'admin@banka.com',
      issuedAt,
      expiresAt,
      nonce: sharedNonce,
      signature: sig2
    });

    assert.strictEqual(replayRun.status, 'Rejected');
    assert.match(replayRun.error || '', /REPLAY_ATTACK_REJECTED/);
  });

  it('Rejects expired commands based on short TTL', async () => {
    const cmdId = `agent-cmd-exp-${Date.now()}`;
    const nonce = `agent-nonce-exp-${Date.now()}`;
    const issuedAt = new Date(Date.now() - 120000).toISOString();
    const expiresAt = new Date(Date.now() - 30000).toISOString(); // Expired 30 seconds ago
    const params = {};

    const sig = computeCommandSignature(
      testSecret,
      cmdId,
      'DEV-TEST-01',
      'force_logout',
      params,
      'admin@banka.com',
      issuedAt,
      expiresAt,
      nonce
    );

    const res = await executor.executeCommand({
      id: cmdId,
      deviceId: 'DEV-TEST-01',
      action: 'force_logout',
      params,
      issuedBy: 'admin@banka.com',
      issuedAt,
      expiresAt,
      nonce,
      signature: sig
    });

    assert.strictEqual(res.status, 'Rejected');
    assert.match(res.error || '', /EXPIRED_COMMAND/);
  });

  it('Blocks path traversal in quarantine_file', async () => {
    const cmdId = `agent-cmd-trav-${Date.now()}`;
    const nonce = `agent-nonce-trav-${Date.now()}`;
    const issuedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 60000).toISOString();
    const params = { filename: '../../../etc/passwd' };

    const sig = computeCommandSignature(
      testSecret,
      cmdId,
      'DEV-TEST-01',
      'quarantine_file',
      params,
      'admin@banka.com',
      issuedAt,
      expiresAt,
      nonce
    );

    const res = await executor.executeCommand({
      id: cmdId,
      deviceId: 'DEV-TEST-01',
      action: 'quarantine_file',
      params,
      issuedBy: 'admin@banka.com',
      issuedAt,
      expiresAt,
      nonce,
      signature: sig
    });

    assert.strictEqual(res.status, 'Failed');
    assert.match(res.error || '', /PATH_TRAVERSAL_BLOCKED/);
  });

  it('Blocks arbitrary process kill outside demo_suspicious', async () => {
    const cmdId = `agent-cmd-kill-${Date.now()}`;
    const nonce = `agent-nonce-kill-${Date.now()}`;
    const issuedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 60000).toISOString();
    const params = { processName: 'explorer.exe' };

    const sig = computeCommandSignature(
      testSecret,
      cmdId,
      'DEV-TEST-01',
      'kill_process',
      params,
      'admin@banka.com',
      issuedAt,
      expiresAt,
      nonce
    );

    const res = await executor.executeCommand({
      id: cmdId,
      deviceId: 'DEV-TEST-01',
      action: 'kill_process',
      params,
      issuedBy: 'admin@banka.com',
      issuedAt,
      expiresAt,
      nonce,
      signature: sig
    });

    assert.strictEqual(res.status, 'Failed');
    assert.match(res.error || '', /SECURITY_VIOLATION/);
  });
});

