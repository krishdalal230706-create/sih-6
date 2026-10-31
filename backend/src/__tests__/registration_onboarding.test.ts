process.env.DEMO_MODE = 'true';

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import http from 'http';
import express, { Response } from 'express';
import { endpointDb } from '../db/endpointDb.js';
import { authRouter } from '../routes/auth.js';
import { accountSecurityRouter } from '../routes/accountSecurity.js';
import { db } from '../models/db.js';
import { requireAuth, requireAdmin, AuthenticatedRequest } from '../middleware/authMiddleware.js';

const app = express();
app.use(express.json());
app.use('/api/auth', authRouter);
app.use('/api/account-security', accountSecurityRouter);

// Organizations routes for testing
app.get('/api/organizations/join-code', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const org = endpointDb.getOrgById(req.user!.orgId);
  if (!org) return res.status(404).json({ error: 'NOT_FOUND' });
  res.json({ joinCode: org.join_code, requiresApproval: org.requires_approval === 1 });
});

app.post('/api/organizations/join-code/regenerate', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const newCode = `REGEN-${Date.now().toString().slice(-4)}`;
  endpointDb.updateOrgJoinCode(req.user!.orgId, newCode);
  res.json({ success: true, joinCode: newCode });
});

app.get('/api/organizations/:id', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  if (req.params.id !== req.user!.orgId) {
    return res.status(403).json({ error: 'FORBIDDEN_ORG', message: 'Access denied: You cannot view profile of another organization.' });
  }
  const org = db.organizations[req.params.id];
  res.json({ organization: org });
});

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
          let parsed = {};
          try {
            parsed = raw ? JSON.parse(raw) : {};
          } catch {
            parsed = { rawText: raw };
          }
          resolve({ status: res.statusCode || 500, data: parsed });
        });
      }
    );

    req.on('error', reject);
    if (payload) {
      req.write(payload);
    }
    req.end();
  });
}

describe('Phase 1: Registration, Organization Onboarding & Auth Lifecycle', () => {
  before(async () => {
    endpointDb.seedDefaultsIfEmpty();
    await new Promise<void>((resolve) => {
      server = http.createServer(app);
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address() as any;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  it('1. Successfully registers a standard user using a valid join code (BANK-A01) -> login -> my-account', async () => {
    const email = `testuser_${Date.now()}@domain.com`;
    const regRes = await makeRequest('POST', '/api/auth/register', {
      name: 'Test New User',
      email,
      password: 'SecurePass123!',
      joinCode: 'BANK-A01'
    });

    assert.strictEqual(regRes.status, 201);
    assert.strictEqual(regRes.data.success, true);
    assert.strictEqual(regRes.data.user.role, 'user', 'Must strictly assign role=user');
    assert.strictEqual(regRes.data.user.orgId, 'org-1');

    // Login as the newly registered user
    const loginRes = await makeRequest('POST', '/api/auth/login', {
      email,
      password: 'SecurePass123!'
    });
    assert.strictEqual(loginRes.status, 200);
    assert.ok(loginRes.data.token, 'Must return JWT token');
    assert.strictEqual(loginRes.data.user.role, 'user');

    // Access user portal endpoint
    const myAccountRes = await makeRequest('GET', '/api/auth/my-account', undefined, loginRes.data.token);
    assert.strictEqual(myAccountRes.status, 200);
    assert.strictEqual(myAccountRes.data.user.email, email.toLowerCase());
  });

  it('2. Rejects registration with duplicate email with 409 Conflict', async () => {
    const res = await makeRequest('POST', '/api/auth/register', {
      name: 'Duplicate Bob',
      email: 'alice@banka.com', // Already seeded
      password: 'Password123!',
      joinCode: 'BANK-A01'
    });

    assert.strictEqual(res.status, 409);
    assert.strictEqual(res.data.error, 'EMAIL_ALREADY_REGISTERED');
  });

  it('3. Rejects invalid email formatting with 400 Bad Request', async () => {
    const res = await makeRequest('POST', '/api/auth/register', {
      name: 'Invalid Email Person',
      email: 'not-a-valid-email',
      password: 'Password123!',
      joinCode: 'BANK-A01'
    });

    assert.strictEqual(res.status, 400);
    assert.strictEqual(res.data.error, 'INVALID_INPUT');
  });

  it('4. Rejects weak password (requires min 8 chars with letters and numbers)', async () => {
    const weak1 = await makeRequest('POST', '/api/auth/register', {
      name: 'Weak Pass Person',
      email: 'weakpass1@domain.com',
      password: 'short',
      joinCode: 'BANK-A01'
    });
    assert.strictEqual(weak1.status, 400);

    const weak2 = await makeRequest('POST', '/api/auth/register', {
      name: 'Weak Pass Person',
      email: 'weakpass2@domain.com',
      password: 'letterswithoutdigits',
      joinCode: 'BANK-A01'
    });
    assert.strictEqual(weak2.status, 400);
  });

  it('5. Rejects wrong or expired organization join code with generic error', async () => {
    const res = await makeRequest('POST', '/api/auth/register', {
      name: 'Wrong Code Person',
      email: `wrongcode_${Date.now()}@domain.com`,
      password: 'Password123!',
      joinCode: 'NON-EXISTENT-CODE'
    });

    assert.strictEqual(res.status, 400);
    assert.strictEqual(res.data.error, 'INVALID_JOIN_CODE');
  });

  it('6. Join code can NEVER create an admin even if role="admin" is injected in payload', async () => {
    const email = `hacker_${Date.now()}@domain.com`;
    const res = await makeRequest('POST', '/api/auth/register', {
      name: 'Malicious Actor',
      email,
      password: 'Password123!',
      joinCode: 'BANK-A01',
      role: 'admin' // Attempt privilege injection
    } as any);

    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.data.user.role, 'user', 'Injected admin role must be completely ignored');

    const dbUser = endpointDb.getUserByEmail(email);
    assert.strictEqual(dbUser?.role, 'user');
    assert.strictEqual(dbUser?.privilege_level, 'STANDARD');
  });

  it('7. Registers new organization with first admin, unique 8-char join code, and valid baseline risk posture', async () => {
    const adminEmail = `admin_aero_${Date.now()}@defenseaero.com`;
    const res = await makeRequest('POST', '/api/auth/register-organization', {
      orgName: 'Aero Defense Systems',
      orgType: 'Defense & Aerospace',
      adminName: 'Col. Samantha Carter',
      email: adminEmail,
      password: 'AdminPassword123!',
      cyberProfile: {
        usersCount: 500,
        criticalSystems: 35,
        internetFacingServices: 10,
        authenticationMethods: ['Password', 'Smart Card MFA'],
        securityControls: ['Firewall', 'Zero Trust Network', 'EDR'],
        dataSensitivity: 'CRITICAL',
        previousIncidents: 0
      }
    });

    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.data.success, true);
    assert.ok(res.data.token, 'Must return admin JWT token');
    assert.strictEqual(res.data.user.role, 'admin');
    assert.ok(res.data.org.joinCode, 'Must generate unique join code');
    assert.strictEqual(res.data.org.joinCode.length >= 8, true);
    assert.strictEqual(typeof res.data.org.riskScore, 'number');
    assert.strictEqual(isNaN(res.data.org.riskScore), false);
    assert.ok(res.data.org.riskScore > 0 && res.data.org.riskScore <= 100);

    // Verify admin can access their own join code
    const joinCodeRes = await makeRequest('GET', '/api/organizations/join-code', undefined, res.data.token);
    assert.strictEqual(joinCodeRes.status, 200);
    assert.strictEqual(joinCodeRes.data.joinCode, res.data.org.joinCode);
  });

  it('8. Cross-Tenant Isolation: Admin of newly registered org CANNOT view or tamper with Bank A data', async () => {
    // 1. Create new org admin
    const adminEmail = `admin_isolated_${Date.now()}@secureorg.com`;
    const regRes = await makeRequest('POST', '/api/auth/register-organization', {
      orgName: 'Isolated Corp',
      orgType: 'Finance',
      adminName: 'Chief Admin',
      email: adminEmail,
      password: 'AdminPassword123!'
    });
    const isolatedToken = regRes.data.token;

    // 2. Attempt to access Bank A (org-1)
    const crossRes = await makeRequest('GET', '/api/organizations/org-1', undefined, isolatedToken);
    assert.strictEqual(crossRes.status, 403, 'Must return 403 Forbidden for cross-org access');
    assert.strictEqual(crossRes.data.error, 'FORBIDDEN_ORG');
  });

  it('9. Email Verification and Forgot-Password Flow: Request code -> Verify code -> Set new password -> Sign in', async () => {
    // 1. Register a test user
    const email = `forgot_${Date.now()}@resetdomain.com`;
    await makeRequest('POST', '/api/auth/register', {
      name: 'Reset Test User',
      email,
      password: 'OldPassword123!',
      joinCode: 'BANK-A01'
    });

    // 2. Request forgot-password verification code
    const reqCodeRes = await makeRequest('POST', '/api/auth/forgot-password/request', { email });
    assert.strictEqual(reqCodeRes.status, 200);
    assert.strictEqual(reqCodeRes.data.success, true);
    assert.ok(reqCodeRes.data.demoCode, 'Demo code must be supplied in demo mode');
    const demoCode = reqCodeRes.data.demoCode;

    // 3. Verify code
    const verifyRes = await makeRequest('POST', '/api/auth/forgot-password/verify', {
      email,
      code: demoCode
    });
    assert.strictEqual(verifyRes.status, 200);
    assert.ok(verifyRes.data.resetToken, 'Must issue reset token upon valid code');
    const resetToken = verifyRes.data.resetToken;

    // 4. Reset password
    const resetRes = await makeRequest('POST', '/api/auth/forgot-password/reset', {
      email,
      resetToken,
      newPassword: 'BrandNewPassword123!'
    });
    assert.strictEqual(resetRes.status, 200);

    // 5. Old password must now fail
    const oldLogin = await makeRequest('POST', '/api/auth/login', {
      email,
      password: 'OldPassword123!'
    });
    assert.strictEqual(oldLogin.status, 401);

    // 6. New password must succeed
    const newLogin = await makeRequest('POST', '/api/auth/login', {
      email,
      password: 'BrandNewPassword123!'
    });
    assert.strictEqual(newLogin.status, 200);
    assert.ok(newLogin.data.token);
  });
});

