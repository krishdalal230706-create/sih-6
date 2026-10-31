import { test, describe, before } from 'node:test';
import assert from 'node:assert';
import { endpointDb } from '../db/endpointDb.js';
import { accountDetectionEngine } from '../engine/accountDetectionEngine.js';
import { db } from '../models/db.js';

describe('Module 8 Phase 2: Account Attack Detection Engine & Waterfall Tests', () => {
  before(() => {
    endpointDb.seedDefaultsIfEmpty();
  });

  test('RULE-AUTH-01: Rapid failed logins trigger credential stuffing alert', () => {
    const user = endpointDb.getUserByEmail('alice@banka.com')!;
    const now = Date.now();

    // 5 rapid failed logins in 60s
    let lastAlert: any = null;
    for (let i = 1; i <= 5; i++) {
      lastAlert = accountDetectionEngine.recordEventAndEvaluate(user, {
        eventType: 'FAILED_LOGIN',
        ipAddress: '198.51.100.99',
        deviceFingerprint: 'Mozilla/5.0 Test Browser',
        location: 'New York, US',
        details: 'Incorrect password entered',
        timestamp: now - (60 - i * 10) * 1000
      });
    }

    assert.ok(lastAlert, 'Alert must be triggered on 5th failed attempt');
    assert.strictEqual(lastAlert.userId, user.id);
    assert.strictEqual(lastAlert.status, 'New');
    assert.ok(lastAlert.matchedRules.some((r: string) => r.includes('RULE-AUTH-01')));
    assert.ok(lastAlert.confidence >= 80, 'Confidence must be at least 80%');

    // Check waterfall per-factor contribution
    const authFactor = lastAlert.factorContributions.find((fc: any) => fc.category === 'Authentication');
    assert.ok(authFactor);
    assert.ok(authFactor.points >= 20);
    assert.ok(authFactor.explanation.includes('repeated failed'));
  });

  test('RULE-AUTH-02: Successful login following brute-force streak triggers critical alert', () => {
    const user = endpointDb.getUserByEmail('bob@banka.com')!;
    const now = Date.now();

    // Inject 3 failures then 1 success
    for (let i = 1; i <= 3; i++) {
      accountDetectionEngine.recordEventAndEvaluate(user, {
        eventType: 'FAILED_LOGIN',
        ipAddress: '203.0.113.50',
        timestamp: now - 30000 + i * 1000
      });
    }

    const successAlert = accountDetectionEngine.recordEventAndEvaluate(user, {
      eventType: 'SUCCESSFUL_LOGIN',
      ipAddress: '203.0.113.50',
      timestamp: now
    });

    assert.ok(successAlert);
    assert.ok(successAlert.matchedRules.some((r: string) => r.includes('RULE-AUTH-02')));
    assert.strictEqual(successAlert.severity, 'CRITICAL');
  });

  test('Deterministic Alert IDs: Ensures demo reproducibility without Math.random', () => {
    const user = endpointDb.getUserByEmail('clara@hospitalb.org')!;
    const simAlert = accountDetectionEngine.simulateAccountAttack(user.id);

    assert.ok(simAlert);
    assert.strictEqual(simAlert.id, `alt-${user.id.toLowerCase().replace(/[^a-z0-9]/g, '')}`);
    assert.strictEqual(simAlert.id.includes('random'), false);

    // Verify stored in database
    const dbAlert = endpointDb.getAccountAlertById(simAlert.id);
    assert.ok(dbAlert);
    assert.strictEqual(dbAlert.user_email, 'clara@hospitalb.org');
  });

  test('Full Multi-Vector Simulation: Evaluates all 6 attack rules and computes risk waterfall', () => {
    const user = endpointDb.getUserByEmail('emma@univc.edu')!;
    const orgBaselineRisk = db.organizations['org-3']?.riskScore || 50;

    const simAlert = accountDetectionEngine.simulateAccountAttack(user.id);

    // Verify matched rules span multi-vector attack
    assert.ok(simAlert.matchedRules.some((r) => r.includes('RULE-AUTH-01')), 'Rule 1 must match');
    assert.ok(simAlert.matchedRules.some((r) => r.includes('RULE-AUTH-02')), 'Rule 2 must match');
    assert.ok(simAlert.matchedRules.some((r) => r.includes('RULE-DEV-03')), 'Rule 3 must match');
    assert.ok(simAlert.matchedRules.some((r) => r.includes('RULE-GEO-04')), 'Rule 4 must match');
    assert.ok(simAlert.matchedRules.some((r) => r.includes('RULE-PRIV-05')), 'Rule 5 must match');
    assert.ok(simAlert.matchedRules.some((r) => r.includes('RULE-DATA-06')), 'Rule 6 must match');

    assert.ok(simAlert.confidence >= 90, 'Multi-stage attack should yield high confidence (>=90%)');
    assert.ok(simAlert.accountRiskScore >= 85, 'Account risk score should be in critical band');

    // Waterfall explainability contributions must cover multiple categories
    const categories = simAlert.factorContributions.map((fc) => fc.category);
    assert.ok(categories.includes('Authentication'));
    assert.ok(categories.includes('Device Security'));
    assert.ok(categories.includes('Geographic Velocity'));
    assert.ok(categories.includes('Privilege'));
    assert.ok(categories.includes('Data Access'));

    // Verify org risk increased in shared riskEngine
    const updatedOrg = db.organizations['org-3'];
    assert.ok(updatedOrg.riskScore >= orgBaselineRisk, 'Org risk score must increase upon attack detection');
  });

  test('Remediation workflow: Marks alert Remediated and de-escalates organization risk', () => {
    const user = endpointDb.getUserByEmail('alice@banka.com')!;
    const alertId = `alt-${user.id.toLowerCase().replace(/[^a-z0-9]/g, '')}`;

    const remediateResult = accountDetectionEngine.remediateAlert(alertId, 'admin@banka.com');
    assert.ok(remediateResult);
    assert.strictEqual(remediateResult.alert.status, 'Remediated');
    assert.strictEqual(remediateResult.alert.accountRiskScore, 18);

    const dbAlert = endpointDb.getAccountAlertById(alertId)!;
    assert.strictEqual(dbAlert.status, 'Remediated');
    assert.strictEqual(dbAlert.remediated_by, 'admin@banka.com');
  });
});

