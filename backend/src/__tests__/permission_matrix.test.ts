process.env.DEMO_MODE = 'true';
process.env.ENABLE_ENDPOINT_AGENT = 'false';

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import http from 'http';
import express, { Request, Response } from 'express';
import { endpointDb } from '../db/endpointDb.js';
import { authRouter } from '../routes/auth.js';
import { accountSecurityRouter } from '../routes/accountSecurity.js';
import { auditRouter } from '../routes/audit.js';
import { requireAuth, requireAdmin, requireDemoMode, AuthenticatedRequest } from '../middleware/authMiddleware.js';
import { db } from '../models/db.js';
import { calculateOrganizationRisk } from '../engine/riskEngine.js';
import { AUTH_CONFIG } from '../config/authConfig.js';

import { deviceRouter } from '../routes/devices.js';
import { commandRouter } from '../routes/commands.js';

// Setup ephemeral server with exact production route configuration
const app = express();
app.use(express.json());

app.use('/api/auth', authRouter);
app.use('/api/account-security', accountSecurityRouter);
app.use('/api/audit', auditRouter);

// Gated endpoint module (disabled in prototype)
if (AUTH_CONFIG.ENABLE_ENDPOINT_AGENT) {
  app.use('/api/devices', deviceRouter);
  app.use('/api/commands', commandRouter);
} else {
  const disabledHandler = (_req: Request, res: Response) => {
    res.status(404).json({ error: 'MODULE_DISABLED', message: 'Endpoint Agent module is disabled in this deployment.' });
  };
  app.use('/api/devices', disabledHandler);
  app.use('/api/commands', disabledHandler);
}

// Health check
app.get('/api/health', (_req, res) => {
  res.json({ status: 'Operational' });
});

// Admin SOC routes
app.get('/api/dashboard', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const org = db.organizations[req.user!.orgId];
  res.json({ organization: org });
});

app.get('/api/organizations', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const org = db.organizations[req.user!.orgId];
  res.json({ organizations: [org], activeOrgId: org?.id });
});

app.get('/api/organizations/:id', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  if (req.params.id !== req.user!.orgId) {
    return res.status(403).json({ error: 'FORBIDDEN_ORG', message: 'Access denied: You cannot view profile of another organization.' });
  }
  res.json({ organization: db.organizations[req.params.id] });
});

app.get('/api/risk', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const org = db.organizations[req.user!.orgId];
  res.json({ riskResult: calculateOrganizationRisk(org, 0) });
});

app.get('/api/risk/:organizationId', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  if (req.params.organizationId !== req.user!.orgId) {
    return res.status(403).json({ error: 'FORBIDDEN_ORG', message: 'Access denied: You cannot view cyber risk of another organization.' });
  }
  res.json({ riskResult: calculateOrganizationRisk(db.organizations[req.params.organizationId], 0) });
});

app.get('/api/incidents', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const list = db.incidents.filter((i) => i.orgId === req.user!.orgId);
  res.json({ incidents: list });
});

app.get('/api/response-actions', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const actions = db.responseActions.filter((a) => a.orgId === req.user!.orgId);
  res.json({ responseActions: actions });
});

app.post('/api/ledger/tamper', requireAuth, requireAdmin, requireDemoMode, (_req: AuthenticatedRequest, res: Response) => {
  res.json({ success: true });
});

app.post('/api/ledger/reset', requireAuth, requireAdmin, requireDemoMode, (_req: AuthenticatedRequest, res: Response) => {
  res.json({ success: true });
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
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const payload = body ? JSON.stringify(body) : undefined;
    if (payload) headers['Content-Length'] = Buffer.byteLength(payload).toString();

    const req = http.request(url, { method, headers }, (res) => {
      let raw = '';
      res.on('data', (c) => (raw += c));
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode || 500, data: raw ? JSON.parse(raw) : {} });
        } catch {
          resolve({ status: res.statusCode || 500, data: raw });
        }
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

describe('Phase 1: Multi-Tenant Role & Permission Matrix Verification', () => {
  let adminA_token: string;
  let adminB_token: string;
  let userA_token: string;

  before(async () => {
    endpointDb.resetToBaseline();
    server = http.createServer(app);
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address() as any;
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });

    // 1. Authenticate Admin A (Bank A)
    const resAdminA = await makeRequest('POST', '/api/auth/login', {
      email: 'admin@banka.com',
      password: 'AdminPass123!'
    });
    adminA_token = resAdminA.data.token;

    // 2. Authenticate Admin B (Hospital B)
    const resAdminB = await makeRequest('POST', '/api/auth/login', {
      email: 'admin@hospitalb.org',
      password: 'AdminPass123!'
    });
    adminB_token = resAdminB.data.token;

    // 3. Authenticate User A (Alice Walker, Bank A)
    const resUserA = await makeRequest('POST', '/api/auth/login', {
      email: 'alice@banka.com',
      password: 'UserPass123!'
    });
    userA_token = resUserA.data.token;
  });

  after(async () => {
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  // --- ANONYMOUS ACCESS TESTS ---
  it('Matrix 1: Anonymous visitor can only access public health and login routes; all SOC routes return 401', async () => {
    // Public routes
    const health = await makeRequest('GET', '/api/health');
    assert.strictEqual(health.status, 200);

    const demoUsers = await makeRequest('GET', '/api/auth/demo-users');
    assert.strictEqual(demoUsers.status, 200);
    // Crucial: Passwords MUST NOT be exposed in demo-users!
    for (const acct of demoUsers.data.accounts) {
      assert.strictEqual((acct as any).password, undefined, 'Demo user account must never leak password');
    }

    // Protected SOC routes return 401 Unauthorized
    const routes401 = [
      ['GET', '/api/dashboard'],
      ['GET', '/api/organizations'],
      ['GET', '/api/risk'],
      ['GET', '/api/incidents'],
      ['GET', '/api/audit'],
      ['GET', '/api/account-security/alerts'],
      ['POST', '/api/account-security/simulate'],
      ['POST', '/api/account-security/fix']
    ];

    for (const [m, p] of routes401) {
      const res = await makeRequest(m, p);
      assert.strictEqual(res.status, 401, `Anonymous request to ${m} ${p} must return 401`);
    }

    // Deprecated public attack route must return 404 (removed)
    const simPublic = await makeRequest('POST', '/api/account-security/simulate-login-attack', { email: 'alice@banka.com' });
    assert.strictEqual(simPublic.status, 404, 'Public simulate-login-attack endpoint must be removed');
  });

  // --- STANDARD USER ROLE TESTS ---
  it('Matrix 2: Standard User (role=user) accesses only My Account; all SOC routes return 403 Forbidden', async () => {
    // User can access their own profile and account
    const me = await makeRequest('GET', '/api/auth/me', undefined, userA_token);
    assert.strictEqual(me.status, 200);
    assert.strictEqual(me.data.user.email, 'alice@banka.com');

    const myAccount = await makeRequest('GET', '/api/auth/my-account', undefined, userA_token);
    assert.strictEqual(myAccount.status, 200);
    assert.strictEqual(myAccount.data.user.role, 'user');

    // User can simulate attack ONLY on their own account
    const simSelf = await makeRequest('POST', '/api/account-security/simulate', { userId: 'usr-bank-alice' }, userA_token);
    assert.strictEqual(simSelf.status, 200);

    // User is blocked from simulating attacks on other users (403)
    const simOther = await makeRequest('POST', '/api/account-security/simulate', { userId: 'usr-bank-bob' }, userA_token);
    assert.strictEqual(simOther.status, 403, 'User cannot simulate attack on other accounts');

    // User calling SOC admin APIs must receive 403
    const adminRoutes: Array<[string, string, any?]> = [
      ['GET', '/api/dashboard'],
      ['GET', '/api/organizations'],
      ['GET', '/api/risk'],
      ['GET', '/api/incidents'],
      ['GET', '/api/response-actions'],
      ['GET', '/api/account-security/alerts'],
      ['POST', '/api/account-security/fix', { userId: 'usr-bank-alice', action: 'lock_account' }],
      ['GET', '/api/audit'],
      ['POST', '/api/ledger/tamper', { blockNumber: 10420 }],
      ['POST', '/api/ledger/reset']
    ];

    for (const [m, p, b] of adminRoutes) {
      const res = await makeRequest(m, p, b, userA_token);
      assert.strictEqual(res.status, 403, `Standard user calling ${m} ${p} must be rejected with 403`);
    }
  });

  // --- ADMIN OF ORG A TESTS ---
  it('Matrix 3: Admin of Org A (Bank A) accesses Bank A data, but is blocked from Org B (Hospital B) data with 403', async () => {
    // Admin A can access Bank A dashboard and org profile
    const dash = await makeRequest('GET', '/api/dashboard', undefined, adminA_token);
    assert.strictEqual(dash.status, 200);
    assert.strictEqual(dash.data.organization.id, 'org-1');

    const orgs = await makeRequest('GET', '/api/organizations', undefined, adminA_token);
    assert.strictEqual(orgs.status, 200);
    assert.strictEqual(orgs.data.organizations.length, 1);
    assert.strictEqual(orgs.data.organizations[0].id, 'org-1');

    // Admin A accessing Org A directly succeeds
    const org1 = await makeRequest('GET', '/api/organizations/org-1', undefined, adminA_token);
    assert.strictEqual(org1.status, 200);

    // Admin A attempting to access Org B profile returns 403
    const org2 = await makeRequest('GET', '/api/organizations/org-2', undefined, adminA_token);
    assert.strictEqual(org2.status, 403, 'Admin A accessing Org B must return 403');

    // Admin A attempting to access Org B risk returns 403
    const risk2 = await makeRequest('GET', '/api/risk/org-2', undefined, adminA_token);
    assert.strictEqual(risk2.status, 403, 'Admin A accessing Org B risk must return 403');

    // Admin A attempting to execute remote fix on Org B user returns 403
    const fixOrgBUser = await makeRequest('POST', '/api/account-security/fix', {
      userId: 'usr-hosp-clara',
      action: 'lock_account'
    }, adminA_token);
    assert.strictEqual(fixOrgBUser.status, 403, 'Admin A cannot execute remote fix on Org B user');

    // Admin A executing remote fix on Org A user succeeds
    const fixOrgAUser = await makeRequest('POST', '/api/account-security/fix', {
      userId: 'usr-bank-alice',
      action: 'lock_account'
    }, adminA_token);
    assert.strictEqual(fixOrgAUser.status, 200);
  });

  // --- ADMIN OF ORG B TESTS & ISOLATION ---
  it('Matrix 4: Admin of Org B (Hospital B) is strictly isolated and cannot view Org A users or alerts', async () => {
    // Admin B dashboard is scoped to org-2
    const dashB = await makeRequest('GET', '/api/dashboard', undefined, adminB_token);
    assert.strictEqual(dashB.status, 200);
    assert.strictEqual(dashB.data.organization.id, 'org-2');

    // Admin B cannot view Org A details
    const org1FromB = await makeRequest('GET', '/api/organizations/org-1', undefined, adminB_token);
    assert.strictEqual(org1FromB.status, 403);

    // Admin B cannot view Bank A user account security details
    const userDetailFromB = await makeRequest('GET', '/api/account-security/users/usr-bank-alice/details', undefined, adminB_token);
    assert.strictEqual(userDetailFromB.status, 403, 'Admin B cannot view Bank A user details');
  });

  // --- ENDPOINT AGENT GATING ---
  it('Matrix 5: Endpoint agent routes return 404 when ENABLE_ENDPOINT_AGENT=false', async () => {
    const devices = await makeRequest('GET', '/api/devices', undefined, adminA_token);
    assert.strictEqual(devices.status, 404, 'Disabled endpoint agent module must return 404');

    const commands = await makeRequest('POST', '/api/commands/issue', {
      deviceId: 'DEV-BANK-01',
      action: 'force_logout'
    }, adminA_token);
    assert.strictEqual(commands.status, 404, 'Disabled command issuance must return 404');
  });

  // --- REAL-TIME LOCKED USER GATING ---
  it('Matrix 6: Auth middleware checks DB status on EVERY request; locked user is immediately barred (403)', async () => {
    // User A was locked in Matrix 3 test
    const checkMe = await makeRequest('GET', '/api/auth/me', undefined, userA_token);
    assert.strictEqual(checkMe.status, 403, 'Locked user must be immediately barred on next API request');
    assert.strictEqual(checkMe.data.error, 'ACCOUNT_LOCKED');
  });
});
