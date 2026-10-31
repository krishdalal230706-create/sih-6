process.env.DEMO_MODE = 'true';

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import http from 'http';
import express, { Response } from 'express';
import bcrypt from 'bcryptjs';
import { endpointDb } from '../db/endpointDb.js';
import { authRouter } from '../routes/auth.js';
import { requireAuth, AuthenticatedRequest } from '../middleware/authMiddleware.js';

const app = express();
app.use(express.json());
app.use('/api/auth', authRouter);

let server: http.Server;
let baseUrl: string;

function makeRequest(
  method: string,
  path: string,
  body?: any,
  token?: string
): Promise<{ status: number; data: any }> {
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
          let data: any = {};
          try {
            data = JSON.parse(raw);
          } catch {
            data = raw;
          }
          resolve({ status: res.statusCode || 500, data });
        });
      }
    );

    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

describe('Phase 2 User Portal Endpoints', () => {
  let userToken: string;
  let userEmail = 'user_portal_test@banka.com';
  let userId: string;

  before(async () => {
    // Seed test user
    const existing = endpointDb.getUserByEmail(userEmail);
    if (!existing) {
      const passwordHash = await bcrypt.hash('UserPass123!', 10);
      endpointDb.createUser({
        id: 'user-portal-test',
        org_id: 'org-1',
        name: 'Portal Test User',
        email: userEmail,
        password_hash: passwordHash,
        role: 'user',
        status: 'active',
        mfa_required: 0,
        privilege_level: 'STANDARD',
        must_reset: 0,
        created_at: new Date().toISOString()
      });
    } else {
      // Ensure org is org-1
      (endpointDb as any).db.prepare('UPDATE users SET org_id = ? WHERE email = ?').run('org-1', userEmail);
    }

    server = http.createServer(app);
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address() as any;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    // Login user
    const res = await makeRequest('POST', '/api/auth/login', {
      email: userEmail,
      password: 'UserPass123!'
    });
    assert.strictEqual(res.status, 200);
    userToken = res.data.token;
    userId = res.data.user.id;
  });

  after(async () => {
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it('1. GET /api/auth/my-account returns user profile, reports, and active sessions count', async () => {
    const res = await makeRequest('GET', '/api/auth/my-account', undefined, userToken);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.data.user.email, userEmail);
    assert.strictEqual(res.data.user.role, 'user');
    assert.ok(res.data.orgName.includes('Bank'));
    assert.ok(Array.isArray(res.data.reports));
    assert.ok(Array.isArray(res.data.recentSignIns));
    assert.ok(Array.isArray(res.data.notices));
    assert.ok(typeof res.data.activeSessionsCount === 'number');
    assert.ok(res.data.activeSessionsCount >= 1);
  });

  it('2. POST /api/auth/report-suspicious creates report visible to the user and logs alert', async () => {
    const res = await makeRequest(
      'POST',
      '/api/auth/report-suspicious',
      {
        title: 'Unrecognized IP sign-in detected',
        details: 'I noticed a login from an unknown browser and location at 2:00 AM.'
      },
      userToken
    );
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.data.success, true);
    assert.ok(res.data.incidentId);

    // Verify report shows up in /api/auth/my-account
    const accRes = await makeRequest('GET', '/api/auth/my-account', undefined, userToken);
    assert.strictEqual(accRes.status, 200);
    const found = accRes.data.reports.find((r: any) => r.id === res.data.incidentId);
    assert.ok(found, 'Report should be listed in user account');
    assert.ok(found.title.includes('SUSPICIOUS ACTIVITY'));
    assert.ok(found.summary.includes('I noticed a login from an unknown browser'));
    assert.strictEqual(found.status, 'New');
  });

  it('3. POST /api/auth/sign-out-other-devices revokes other sessions', async () => {
    // Generate a second session token by logging in again
    const secondLogin = await makeRequest('POST', '/api/auth/login', {
      email: userEmail,
      password: 'UserPass123!'
    });
    assert.strictEqual(secondLogin.status, 200);
    const secondToken = secondLogin.data.token;

    // Check account with second token shows at least 2 active sessions
    let accRes = await makeRequest('GET', '/api/auth/my-account', undefined, secondToken);
    assert.strictEqual(accRes.status, 200);
    assert.ok(accRes.data.activeSessionsCount >= 2);

    // Call sign-out-other-devices using secondToken
    const revokeRes = await makeRequest('POST', '/api/auth/sign-out-other-devices', {}, secondToken);
    assert.strictEqual(revokeRes.status, 200);
    assert.strictEqual(revokeRes.data.success, true);
    assert.strictEqual(revokeRes.data.activeSessions, 1);

    // First token should now be rejected (revoked)
    const firstCheck = await makeRequest('GET', '/api/auth/my-account', undefined, userToken);
    assert.strictEqual(firstCheck.status, 401);

    // Second token remains valid and has activeSessionsCount = 1
    accRes = await makeRequest('GET', '/api/auth/my-account', undefined, secondToken);
    assert.strictEqual(accRes.status, 200);
    assert.strictEqual(accRes.data.activeSessionsCount, 1);

    // Update userToken for remaining tests
    userToken = secondToken;
  });

  it('4. MFA flow: request code and toggle MFA enabled/disabled', async () => {
    // Request code
    const reqRes = await makeRequest('POST', '/api/auth/mfa/request', {}, userToken);
    assert.strictEqual(reqRes.status, 200);
    assert.strictEqual(reqRes.data.success, true);
    assert.ok(reqRes.data.demoCode, 'Demo code should be provided in DEMO_MODE');

    const demoCode = reqRes.data.demoCode;

    // Reject wrong code
    const wrongRes = await makeRequest('POST', '/api/auth/mfa/toggle', { code: '000000', enabled: true }, userToken);
    assert.strictEqual(wrongRes.status, 400);

    // Accept valid code
    const toggleRes = await makeRequest('POST', '/api/auth/mfa/toggle', { code: demoCode, enabled: true }, userToken);
    assert.strictEqual(toggleRes.status, 200);
    assert.strictEqual(toggleRes.data.mfaEnabled, true);

    // Verify in my-account
    const accRes = await makeRequest('GET', '/api/auth/my-account', undefined, userToken);
    assert.strictEqual(accRes.status, 200);
    assert.strictEqual(accRes.data.user.mfaEnabled, true);

    // Toggle off with new code
    const reqOff = await makeRequest('POST', '/api/auth/mfa/request', {}, userToken);
    assert.strictEqual(reqOff.status, 200);
    const codeOff = reqOff.data.demoCode;

    const toggleOff = await makeRequest('POST', '/api/auth/mfa/toggle', { code: codeOff, enabled: false }, userToken);
    assert.strictEqual(toggleOff.status, 200);
    assert.strictEqual(toggleOff.data.mfaEnabled, false);
  });

  it('5. POST /api/auth/change-password updates password securely', async () => {
    const changeRes = await makeRequest(
      'POST',
      '/api/auth/change-password',
      {
        currentPassword: 'UserPass123!',
        newPassword: 'BrandNewPassword99!'
      },
      userToken
    );
    assert.strictEqual(changeRes.status, 200);
    assert.strictEqual(changeRes.data.success, true);

    // Login with new password succeeds
    const newLogin = await makeRequest('POST', '/api/auth/login', {
      email: userEmail,
      password: 'BrandNewPassword99!'
    });
    assert.strictEqual(newLogin.status, 200);

    // Old password fails
    const oldLogin = await makeRequest('POST', '/api/auth/login', {
      email: userEmail,
      password: 'UserPass123!'
    });
    assert.strictEqual(oldLogin.status, 401);
  });
});
