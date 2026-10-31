import { test, describe, before } from 'node:test';
import assert from 'node:assert';
import { endpointDb } from '../db/endpointDb.js';
import { accountDetectionEngine } from '../engine/accountDetectionEngine.js';
import { db } from '../models/db.js';

describe('Module 8 Phase 4: Admin Remote Fix Actions & Multi-Tenant Enforcement', () => {
  before(() => {
    endpointDb.seedDefaultsIfEmpty();
  });

  test('Action 1: Lock Account sets locked status, revokes sessions, and logs notice', () => {
    const user = endpointDb.getUserByEmail('alice@banka.com')!;
    const dummyToken = 'session-token-alice-lock-test';
    endpointDb.createSession(user.id, dummyToken, 1);
    assert.strictEqual(endpointDb.isSessionValid(dummyToken), true);

    // Admin locks account
    endpointDb.updateUserStatus(user.id, 'locked');
    endpointDb.revokeAllUserSessions(user.id);
    endpointDb.addAccountNotice(user.id, user.org_id, 'ACCOUNT_LOCKED', 'Your account was locked by an administrator.');

    const freshUser = endpointDb.getUserById(user.id)!;
    assert.strictEqual(freshUser.status, 'locked');
    assert.strictEqual(endpointDb.isSessionValid(dummyToken), false, 'Active sessions must be revoked');

    const notices = endpointDb.getAccountNotices(user.id);
    assert.ok(notices.some((n) => n.notice_type === 'ACCOUNT_LOCKED'));
  });

  test('Action 2: Force Logout revokes all active tokens for target user', () => {
    const user = endpointDb.getUserByEmail('bob@banka.com')!;
    const token1 = 'tok-bob-session-1';
    const token2 = 'tok-bob-session-2';
    endpointDb.createSession(user.id, token1, 1);
    endpointDb.createSession(user.id, token2, 1);

    assert.strictEqual(endpointDb.isSessionValid(token1), true);
    assert.strictEqual(endpointDb.isSessionValid(token2), true);

    // Revoke all
    endpointDb.revokeAllUserSessions(user.id);

    assert.strictEqual(endpointDb.isSessionValid(token1), false);
    assert.strictEqual(endpointDb.isSessionValid(token2), false);
  });

  test('Action 3: Force Password Reset sets reset_required status and must_reset flag', () => {
    const user = endpointDb.getUserByEmail('alice@banka.com')!;
    endpointDb.updateUserStatus(user.id, 'reset_required');

    const freshUser = endpointDb.getUserById(user.id)!;
    assert.strictEqual(freshUser.status, 'reset_required');
    assert.strictEqual(freshUser.must_reset, 1);
  });

  test('Action 4: Require MFA enforces mandatory multi-factor policy', () => {
    const user = endpointDb.getUserByEmail('bob@banka.com')!;
    endpointDb.updateUserMfa(user.id, true);

    const freshUser = endpointDb.getUserById(user.id)!;
    assert.strictEqual(freshUser.mfa_required, 1);
  });

  test('Action 5: Block IP and Device denies authentication attempts at perimeter', () => {
    const attackerIp = '198.51.100.222';
    const attackerDevice = 'Malicious-Scraper-UA';

    endpointDb.blockEntity('org-1', 'IP', attackerIp, 'admin@banka.com', 'Brute force containment');
    endpointDb.blockEntity('org-1', 'DEVICE', attackerDevice, 'admin@banka.com', 'Brute force containment');

    const checkIp = endpointDb.isEntityBlocked('org-1', attackerIp, 'other-device');
    assert.strictEqual(checkIp.blocked, true);

    const checkDevice = endpointDb.isEntityBlocked('org-1', 'other-ip', attackerDevice);
    assert.strictEqual(checkDevice.blocked, true);
  });

  test('Action 6: Revert Privileges drops elevated user back to STANDARD', () => {
    const user = endpointDb.getUserByEmail('bob@banka.com')!;
    endpointDb.updateUserPrivilege(user.id, 'ELEVATED');
    assert.strictEqual(endpointDb.getUserById(user.id)!.privilege_level, 'ELEVATED');

    endpointDb.updateUserPrivilege(user.id, 'STANDARD');
    assert.strictEqual(endpointDb.getUserById(user.id)!.privilege_level, 'STANDARD');
  });

  test('Action 7: Unlock and Restore returns user to active status', () => {
    const user = endpointDb.getUserByEmail('alice@banka.com')!;
    endpointDb.updateUserStatus(user.id, 'locked');
    assert.strictEqual(endpointDb.getUserById(user.id)!.status, 'locked');

    endpointDb.updateUserStatus(user.id, 'active');
    assert.strictEqual(endpointDb.getUserById(user.id)!.status, 'active');
  });

  test('Risk Engine De-escalation: Remediation lowers organization risk score across pages', () => {
    const user = endpointDb.getUserByEmail('clara@hospitalb.org')!;
    const simAlert = accountDetectionEngine.simulateAccountAttack(user.id);
    assert.strictEqual(simAlert.status, 'New');

    const orgBefore = db.organizations['org-2'];
    const elevatedRisk = orgBefore.riskScore;

    // Apply remote remediation
    const remediation = accountDetectionEngine.remediateAlert(simAlert.id, 'admin@hospitalb.org');
    assert.ok(remediation);
    assert.strictEqual(remediation.alert.status, 'Remediated');
    assert.ok(remediation.updatedOrgRisk <= elevatedRisk, 'Org risk must decrease after remote fix');

    const orgAfter = db.organizations['org-2'];
    assert.ok(orgAfter.riskScore <= elevatedRisk);
    assert.strictEqual(orgAfter.riskTrend, 'FALLING');
  });
});

