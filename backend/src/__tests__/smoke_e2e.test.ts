process.env.DEMO_MODE = 'true';

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import http from 'http';
import express from 'express';
import { endpointDb } from '../db/endpointDb.js';
import { accountDetectionEngine } from '../engine/accountDetectionEngine.js';
import { authRouter } from '../routes/auth.js';
import { accountSecurityRouter } from '../routes/accountSecurity.js';
import { auditRouter } from '../routes/audit.js';
import { deviceRouter } from '../routes/devices.js';
import { commandRouter } from '../routes/commands.js';

const app = express();
app.use(express.json());
app.use('/api/auth', authRouter);
app.use('/api/account-security', accountSecurityRouter);
app.use('/api/audit', auditRouter);
app.use('/api/devices', deviceRouter);
app.use('/api/commands', commandRouter);

let server: http.Server;
let baseUrl: string;

function makeRequest(
  method: string,
  path: string,
  body?: any,
  token?: string
): Promise<{ status: number; data: any; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const url = new URL(path, baseUrl);
    const headers: Record<string, string> = {
      'Content-Type': 'application/json'
    };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const payload = body ? JSON.stringify(body) : undefined;
    if (payload) {
      headers['Content-Length'] = Buffer.byteLength(payload).toString();
    }

    const req = http.request(
      url,
      {
        method,
        headers
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk) => (raw += chunk));
        res.on('end', () => {
          let parsed = {};
          try {
            parsed = raw ? JSON.parse(raw) : {};
          } catch {
            parsed = { rawText: raw };
          }
          resolve({ status: res.statusCode || 500, data: parsed, headers: res.headers });
        });
      }
    );

    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

describe('Quality Gate: End-to-End Smoke Test Suite & Security Verification', () => {
  let adminToken: string;
  let userToken: string;

  before(async () => {
    // Start an in-process ephemeral test server on an ephemeral port
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const address = server.address() as any;
        baseUrl = `http://127.0.0.1:${address.port}`;
        resolve();
      });
    });

    // Reset database to clean prototype baseline
    endpointDb.resetToBaseline();
    accountDetectionEngine.clearAllAlerts();

    // Login as Admin
    const adminLogin = await makeRequest('POST', '/api/auth/login', {
      email: 'admin@banka.com',
      password: 'AdminPass123!'
    });
    assert.strictEqual(adminLogin.status, 200);
    adminToken = adminLogin.data.token;

    // Login as Standard User
    const userLogin = await makeRequest('POST', '/api/auth/login', {
      email: 'alice@banka.com',
      password: 'UserPass123!'
    });
    assert.strictEqual(userLogin.status, 200);
    userToken = userLogin.data.token;
  });

  after(async () => {
    endpointDb.resetToBaseline();
    accountDetectionEngine.clearAllAlerts();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('Scenario 1: Admin can access every SOC data endpoint with valid data and zero 500 errors', async () => {
    const endpoints = [
      '/api/auth/users',
      '/api/auth/me',
      '/api/account-security/alerts',
      '/api/devices',
      '/api/audit',
      '/api/audit/verify'
    ];

    for (const ep of endpoints) {
      const res = await makeRequest('GET', ep, null, adminToken);
      assert.strictEqual(res.status, 200, `Endpoint ${ep} must return HTTP 200`);
      assert.ok(res.data, `Endpoint ${ep} must return valid data payload`);
    }
  });

  it('Scenario 2: Real failed logins on login endpoint trigger credential stuffing alert', async () => {
    const targetEmail = 'bob@banka.com';

    // Fire 5 rapid incorrect password attempts
    for (let i = 1; i <= 5; i++) {
      const failRes = await makeRequest('POST', '/api/auth/login', {
        email: targetEmail,
        password: `WrongPassword${i}!`
      });
      assert.strictEqual(failRes.status, 401);
    }

    // Check alert created for Bob
    const alertsRes = await makeRequest('GET', '/api/account-security/alerts', null, adminToken);
    assert.strictEqual(alertsRes.status, 200);
    const bobAlert = alertsRes.data.alerts.find((a: any) => a.userEmail === targetEmail);

    assert.ok(bobAlert, 'Failed login streak must automatically trigger an alert in detection engine');
    assert.ok(bobAlert.matchedRules.some((r: string) => r.includes('RULE-AUTH-01')));
    assert.strictEqual(bobAlert.status, 'New');
  });

  it('Scenario 3: Simulated attack triggers instant multi-rule alert with waterfall breakdown', async () => {
    const simRes = await makeRequest('POST', '/api/account-security/simulate', { userId: 'usr-bank-alice' }, adminToken);
    assert.strictEqual(simRes.status, 200);
    assert.strictEqual(simRes.data.success, true);
    assert.ok(simRes.data.alert);
    assert.strictEqual(simRes.data.alert.id, 'alt-usrbankalice');
    assert.strictEqual(simRes.data.alert.severity, 'CRITICAL');
    assert.ok(simRes.data.alert.confidence >= 90);
    assert.ok(simRes.data.alert.factorContributions.length >= 5);
  });

  it('Scenario 4: Admin remote fix actions update user status and drop risk everywhere', async () => {
    // 1. Lock Account
    const lockRes = await makeRequest(
      'POST',
      '/api/account-security/fix',
      { userId: 'usr-bank-alice', action: 'lock_account' },
      adminToken
    );
    assert.strictEqual(lockRes.status, 200);
    assert.strictEqual(lockRes.data.success, true);
    assert.strictEqual(lockRes.data.user.status, 'locked');

    // Verify locked user is rejected at login with HTTP 403 ACCOUNT_LOCKED
    const tryLoginLocked = await makeRequest('POST', '/api/auth/login', {
      email: 'alice@banka.com',
      password: 'UserPass123!'
    });
    assert.strictEqual(tryLoginLocked.status, 403);
    assert.strictEqual(tryLoginLocked.data.error, 'ACCOUNT_LOCKED');

    // 2. Unlock Account
    const unlockRes = await makeRequest(
      'POST',
      '/api/account-security/fix',
      { userId: 'usr-bank-alice', action: 'unlock_restore' },
      adminToken
    );
    assert.strictEqual(unlockRes.status, 200);
    assert.strictEqual(unlockRes.data.user.status, 'active');

    // 3. Force Password Reset
    const resetRes = await makeRequest(
      'POST',
      '/api/account-security/fix',
      { userId: 'usr-bank-alice', action: 'force_password_reset' },
      adminToken
    );
    assert.strictEqual(resetRes.status, 200);
    assert.strictEqual(resetRes.data.user.status, 'reset_required');

    // 4. Require MFA
    const mfaRes = await makeRequest(
      'POST',
      '/api/account-security/fix',
      { userId: 'usr-bank-alice', action: 'require_mfa' },
      adminToken
    );
    assert.strictEqual(mfaRes.status, 200);
    assert.strictEqual(mfaRes.data.user.mfaRequired, true);

    // 5. Block IP / Device Perimeter
    const blockRes = await makeRequest(
      'POST',
      '/api/account-security/fix',
      { userId: 'usr-bank-alice', action: 'block_ip_device', entityValue: '203.0.113.88' },
      adminToken
    );
    assert.strictEqual(blockRes.status, 200);

    // 6. Restore to clean active
    await makeRequest(
      'POST',
      '/api/account-security/fix',
      { userId: 'usr-bank-alice', action: 'unlock_restore' },
      adminToken
    );
  });

  it('Scenario 5: Standard user is blocked from calling admin APIs with HTTP 403', async () => {
    // Obtain active session token for standard user Bob
    const bobLogin = await makeRequest('POST', '/api/auth/login', {
      email: 'bob@banka.com',
      password: 'UserPass123!'
    });
    assert.strictEqual(bobLogin.status, 200);
    const standardUserToken = bobLogin.data.token;

    const adminEndpoints = [
      { method: 'GET', path: '/api/auth/users' },
      { method: 'POST', path: '/api/account-security/simulate', body: { userId: 'usr-bank-alice' } },
      { method: 'POST', path: '/api/account-security/fix', body: { userId: 'usr-bank-bob', action: 'lock_account' } },
      { method: 'POST', path: '/api/account-security/share-pattern', body: { alertId: 'alt-usrbankalice' } },
      { method: 'GET', path: '/api/audit' },
      { method: 'GET', path: '/api/audit/verify' },
      { method: 'POST', path: '/api/audit/anchor-ledger' },
      { method: 'POST', path: '/api/account-security/demo-attack-run' },
      { method: 'POST', path: '/api/account-security/demo-reset' }
    ];

    for (const ep of adminEndpoints) {
      const res = await makeRequest(ep.method, ep.path, ep.body, standardUserToken);
      assert.strictEqual(
        res.status,
        403,
        `Standard user must be rejected with HTTP 403 on ${ep.method} ${ep.path}`
      );
      assert.ok(
        res.data.error && res.data.error.includes('FORBIDDEN'),
        `Error payload must indicate FORBIDDEN access: ${JSON.stringify(res.data)}`
      );
    }
  });

  it('Scenario 6: Reset then rerun yields strictly identical results across multiple runs', async () => {
    // Reset baseline
    const r1 = await makeRequest('POST', '/api/account-security/demo-reset', null, adminToken);
    assert.strictEqual(r1.status, 200);

    // Run 1
    const run1 = await makeRequest('POST', '/api/account-security/demo-attack-run', null, adminToken);
    assert.strictEqual(run1.status, 200);

    // Reset baseline again
    const r2 = await makeRequest('POST', '/api/account-security/demo-reset', null, adminToken);
    assert.strictEqual(r2.status, 200);

    // Run 2
    const run2 = await makeRequest('POST', '/api/account-security/demo-attack-run', null, adminToken);
    assert.strictEqual(run2.status, 200);

    // Assert strictly identical values
    assert.strictEqual(run1.data.alert.id, run2.data.alert.id);
    assert.strictEqual(run1.data.alert.confidence, run2.data.alert.confidence);
    assert.strictEqual(run1.data.alert.accountRiskScore, run2.data.alert.accountRiskScore);
    assert.strictEqual(run1.data.updatedOrgRisk, run2.data.updatedOrgRisk);
    assert.strictEqual(
      run1.data.sanitizationResult.sanitizedPattern.threatPatternId,
      run2.data.sanitizationResult.sanitizedPattern.threatPatternId
    );
    assert.strictEqual(
      run1.data.sanitizationResult.sanitizedPattern.patternHash,
      run2.data.sanitizationResult.sanitizedPattern.patternHash
    );
  });

  it('Scenario 7: Cryptographic audit hash-chain integrity verifies and tamper detection pinpoints broken record', async () => {
    // Audit chain must be intact
    const verifyClean = await makeRequest('GET', '/api/audit/verify', null, adminToken);
    assert.strictEqual(verifyClean.status, 200);
    assert.strictEqual(verifyClean.data.isVerified, true);
    assert.strictEqual(verifyClean.data.brokenId, null);

    // Inject demo tamper
    const tamperRes = await makeRequest('POST', '/api/audit/tamper', {}, adminToken);
    assert.strictEqual(tamperRes.status, 200);
    const tamperedId = tamperRes.data.tamperedId;

    // Verifier must detect breach and pinpoint exact broken ID
    const verifyTampered = await makeRequest('GET', '/api/audit/verify', null, adminToken);
    assert.strictEqual(verifyTampered.status, 200);
    assert.strictEqual(verifyTampered.data.isVerified, false);
    assert.strictEqual(verifyTampered.data.brokenId, tamperedId);

    // Reset restores clean state
    await makeRequest('POST', '/api/account-security/demo-reset', null, adminToken);
    const verifyRestored = await makeRequest('GET', '/api/audit/verify', null, adminToken);
    assert.strictEqual(verifyRestored.data.isVerified, true);
  });
});
