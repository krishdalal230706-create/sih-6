import { test, describe, before } from 'node:test';
import assert from 'node:assert';
import bcrypt from 'bcryptjs';
import { endpointDb, computeAuditHash } from '../db/endpointDb.js';
import { signUserToken, verifyUserToken } from '../middleware/authMiddleware.js';

describe('Module 8 Phase 1: Auth, Roles, and Data Model Tests', () => {
  before(() => {
    endpointDb.seedDefaultsIfEmpty();
  });

  test('Seeds predefined demo users with bcrypt-hashed passwords for Bank A, Hospital B, and Univ C', () => {
    const adminBank = endpointDb.getUserByEmail('admin@banka.com');
    assert.ok(adminBank, 'Bank A admin must exist');
    assert.strictEqual(adminBank.role, 'admin');
    assert.strictEqual(adminBank.org_id, 'org-1');
    assert.ok(bcrypt.compareSync('AdminPass123!', adminBank.password_hash), 'Admin password must match hash');

    const userBank = endpointDb.getUserByEmail('alice@banka.com');
    assert.ok(userBank, 'Alice must exist');
    assert.strictEqual(userBank.role, 'user');
    assert.strictEqual(userBank.org_id, 'org-1');
    assert.ok(bcrypt.compareSync('UserPass123!', userBank.password_hash), 'User password must match hash');

    const adminHosp = endpointDb.getUserByEmail('admin@hospitalb.org');
    assert.ok(adminHosp, 'Hospital B admin must exist');
    assert.strictEqual(adminHosp.org_id, 'org-2');

    const adminUniv = endpointDb.getUserByEmail('admin@univc.edu');
    assert.ok(adminUniv, 'Univ C admin must exist');
    assert.strictEqual(adminUniv.org_id, 'org-3');
  });

  test('Issues verifiable JWT tokens with role, orgId, and userId payload', () => {
    const admin = endpointDb.getUserByEmail('admin@banka.com')!;
    const token = signUserToken(admin);
    assert.ok(token && typeof token === 'string');

    const verified = verifyUserToken(token);
    assert.ok(verified);
    assert.strictEqual(verified.email, 'admin@banka.com');
    assert.strictEqual(verified.role, 'admin');
    assert.strictEqual(verified.orgId, 'org-1');
  });

  test('Rejects invalid or tampered JWT tokens', () => {
    const validToken = signUserToken(endpointDb.getUserByEmail('alice@banka.com')!);
    const tamperedToken = validToken.slice(0, -6) + 'abcdef';
    const verified = verifyUserToken(tamperedToken);
    assert.strictEqual(verified, null, 'Tampered token must not verify');
  });

  test('Session lifecycle: records active session and supports instant revocation', () => {
    const user = endpointDb.getUserByEmail('alice@banka.com')!;
    const dummyToken = `test-token-${Date.now()}`;
    const session = endpointDb.createSession(user.id, dummyToken, 1);

    assert.ok(session.id);
    assert.strictEqual(endpointDb.isSessionValid(dummyToken), true);

    // Revoke session
    endpointDb.revokeSession(dummyToken);
    assert.strictEqual(endpointDb.isSessionValid(dummyToken), false, 'Revoked token must be invalid');
  });

  test('Organization and device scoping: Admin sees org devices; User sees only assigned device', () => {
    const bankDevices = endpointDb.getDevicesByOrg('org-1');
    assert.ok(bankDevices.length >= 2, 'Bank A should have at least 2 seeded devices');
    assert.ok(bankDevices.some((d) => d.id === 'DEV-BANK-01'));
    assert.ok(bankDevices.some((d) => d.id === 'DEV-BANK-02'));

    const alice = endpointDb.getUserByEmail('alice@banka.com')!;
    const aliceDevice = endpointDb.getDeviceByUserId(alice.id);
    assert.ok(aliceDevice);
    assert.strictEqual(aliceDevice.id, 'DEV-BANK-01');
    assert.strictEqual(aliceDevice.hostname, 'ALICE-LAPTOP-W11');
  });

  test('Audit log maintains SHA-256 hash-chain and detects any tampering', () => {
    // Append test audit event
    const record = endpointDb.appendAudit('admin@banka.com', 'org-1', 'TEST_ACTION', 'Unit test audit entry');
    assert.ok(record.hash);
    assert.ok(record.prev_hash);

    // Verify intact chain
    const verifyResult = endpointDb.verifyAuditChain();
    assert.strictEqual(verifyResult.isVerified, true, 'Audit chain must be intact');

    // Simulate tampering with record
    const tamperResult = endpointDb.tamperAuditRecord(record.id);
    assert.strictEqual(tamperResult.success, true);

    // Verify that tamper is immediately caught
    const afterTamper = endpointDb.verifyAuditChain();
    assert.strictEqual(afterTamper.isVerified, false, 'Tampered record must be detected');
    assert.strictEqual(afterTamper.brokenId, record.id, 'Must identify exact broken record');

    // Reset to clean baseline
    endpointDb.resetToBaseline();
    const cleanVerify = endpointDb.verifyAuditChain();
    assert.strictEqual(cleanVerify.isVerified, true, 'Clean baseline audit chain must verify');
  });

  test('Password reset lifecycle: flags must_reset and updates password securely', () => {
    const user = endpointDb.getUserByEmail('bob@banka.com')!;
    endpointDb.updateUserMustReset(user.id, true);

    const updatedUser = endpointDb.getUserById(user.id)!;
    assert.strictEqual(updatedUser.must_reset, 1);

    // User resets password
    const newPassword = 'NewSecretPassword2026!';
    const newHash = bcrypt.hashSync(newPassword, 10);
    endpointDb.updateUserPassword(user.id, newHash);

    const resetUser = endpointDb.getUserById(user.id)!;
    assert.strictEqual(resetUser.must_reset, 0);
    assert.strictEqual(resetUser.status, 'active');
    assert.strictEqual(bcrypt.compareSync(newPassword, resetUser.password_hash), true);
  });

  test('User status lifecycle & privilege levels: active, locked, reset_required', () => {
    const user = endpointDb.getUserByEmail('alice@banka.com')!;
    assert.strictEqual(user.status, 'active');
    assert.strictEqual(user.privilege_level, 'STANDARD');

    // Admin locks account
    endpointDb.updateUserStatus(user.id, 'locked');
    const lockedUser = endpointDb.getUserById(user.id)!;
    assert.strictEqual(lockedUser.status, 'locked');

    // Admin requires reset
    endpointDb.updateUserStatus(user.id, 'reset_required');
    const resetReqUser = endpointDb.getUserById(user.id)!;
    assert.strictEqual(resetReqUser.status, 'reset_required');
    assert.strictEqual(resetReqUser.must_reset, 1);

    // Admin unlocks user
    endpointDb.updateUserStatus(user.id, 'active');
    assert.strictEqual(endpointDb.getUserById(user.id)!.status, 'active');

    // Toggle MFA & privilege level
    endpointDb.updateUserMfa(user.id, true);
    assert.strictEqual(endpointDb.getUserById(user.id)!.mfa_required, 1);

    endpointDb.updateUserPrivilege(user.id, 'ELEVATED');
    assert.strictEqual(endpointDb.getUserById(user.id)!.privilege_level, 'ELEVATED');
  });

  test('Records every login attempt with IP, device, location, and success flag', () => {
    const now = new Date().toISOString();
    const attempt = {
      id: `att-test-${Date.now()}`,
      user_id: 'usr-bank-alice',
      email: 'alice@banka.com',
      org_id: 'org-1',
      success: 0,
      ip_address: '198.51.100.42',
      device_fingerprint: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      location: 'Frankfurt, DE',
      failure_reason: 'INCORRECT_PASSWORD',
      timestamp: now
    };

    endpointDb.recordLoginAttempt(attempt);

    const history = endpointDb.getRecentLoginAttempts('alice@banka.com', 5);
    assert.ok(history.length >= 1);
    assert.strictEqual(history[0].ip_address, '198.51.100.42');
    assert.strictEqual(history[0].location, 'Frankfurt, DE');
    assert.strictEqual(history[0].success, 0);
  });

  test('Blocks IP/Device entities and enforces block checks', () => {
    const testIp = '203.0.113.88';
    const testDevice = 'Adversary-Custom-Scanner-v1';

    // Verify not blocked initially
    const initialCheck = endpointDb.isEntityBlocked('org-1', testIp, testDevice);
    assert.strictEqual(initialCheck.blocked, false);

    // Admin blocks the IP
    endpointDb.blockEntity('org-1', 'IP', testIp, 'admin@banka.com', 'Brute force credential stuffing detected');
    const blockedCheck = endpointDb.isEntityBlocked('org-1', testIp, 'clean-device');
    assert.strictEqual(blockedCheck.blocked, true);
    assert.ok(blockedCheck.reason?.includes('Brute force'));

    // Admin unblocks IP
    endpointDb.unblockEntity('org-1', 'IP', testIp);
    const unblockedCheck = endpointDb.isEntityBlocked('org-1', testIp, 'clean-device');
    assert.strictEqual(unblockedCheck.blocked, false);
  });

  test('Admin sees only users of their own organization', () => {
    const bankUsers = endpointDb.getUsersByOrg('org-1');
    assert.ok(bankUsers.length >= 3);
    assert.ok(bankUsers.every((u) => u.org_id === 'org-1'), 'All returned users must belong to org-1');

    const hospUsers = endpointDb.getUsersByOrg('org-2');
    assert.ok(hospUsers.length >= 3);
    assert.ok(hospUsers.every((u) => u.org_id === 'org-2'), 'All returned users must belong to org-2');

    // Ensure no cross-org pollution
    assert.ok(!bankUsers.some((u) => u.email === 'admin@hospitalb.org'));
    assert.ok(!hospUsers.some((u) => u.email === 'admin@banka.com'));
  });

  test('Admin notices can be queued and dismissed by user', () => {
    const alice = endpointDb.getUserByEmail('alice@banka.com')!;
    endpointDb.addAccountNotice(alice.id, alice.org_id, 'SECURITY_WARNING', 'Your account had 3 failed login attempts.');

    const notices = endpointDb.getAccountNotices(alice.id);
    assert.strictEqual(notices.length, 1);
    assert.strictEqual(notices[0].notice_type, 'SECURITY_WARNING');

    // Dismiss notice
    endpointDb.dismissAccountNotice(notices[0].id);
    const afterDismiss = endpointDb.getAccountNotices(alice.id);
    assert.strictEqual(afterDismiss.length, 0);
  });
});

