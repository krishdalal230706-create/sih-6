import { test, describe, before } from 'node:test';
import assert from 'node:assert';
import { endpointDetectionEngine } from '../engine/endpointDetectionEngine.js';
import { endpointDb } from '../db/endpointDb.js';
import { db } from '../models/db.js';

describe('Module 8 Phase 3: Sliding-Window Detection & Explainability Waterfall', () => {
  before(() => {
    endpointDb.seedDefaultsIfEmpty();
    endpointDetectionEngine.resetBaseline();
  });

  test('Evaluates rapid failed logins and triggers credential stuffing anomaly', () => {
    const deviceId = 'DEV-BANK-01';
    const orgId = 'org-1';

    // Inject 5 failed logins
    let lastResult = null;
    for (let i = 0; i < 5; i++) {
      lastResult = endpointDetectionEngine.processEvent(deviceId, orgId, {
        event_type: 'FAILED_LOGIN',
        details: `Simulated failed login attempt #${i + 1}`,
        severity: 'MEDIUM',
        timestamp: new Date().toISOString()
      });
    }

    assert.ok(lastResult, 'Detection must trigger after 5 rapid failed logins');
    assert.strictEqual(lastResult.detected, true);
    assert.ok(lastResult.matchedRules.some((r) => r.includes('RULE-AUTH-01')));
    assert.ok(lastResult.confidence >= 80, 'Confidence must be at least 80%');

    // Check factor contributions for explainability waterfall
    const authFactor = lastResult.factorContributions.find((f) => f.category === 'Authentication');
    assert.ok(authFactor, 'Must produce Authentication factor contribution');
    assert.ok(authFactor.points > 0);
  });

  test('Correlates multi-stage kill chain and transitions device to COMPROMISED', () => {
    const deviceId = 'DEV-BANK-02';
    const orgId = 'org-1';

    // 1. Multiple failed logins
    for (let i = 0; i < 4; i++) {
      endpointDetectionEngine.processEvent(deviceId, orgId, {
        event_type: 'FAILED_LOGIN',
        details: 'Failed logon',
        severity: 'MEDIUM',
        timestamp: new Date().toISOString()
      });
    }

    // 2. Successful login from new device & unusual location
    endpointDetectionEngine.processEvent(deviceId, orgId, {
      event_type: 'SUCCESSFUL_LOGIN',
      details: 'Logon succeeded',
      severity: 'LOW',
      timestamp: new Date().toISOString()
    });
    endpointDetectionEngine.processEvent(deviceId, orgId, {
      event_type: 'NEW_DEVICE',
      details: 'Unregistered hardware fingerprint DEV-UNKNOWN-889',
      severity: 'HIGH',
      timestamp: new Date().toISOString()
    });
    endpointDetectionEngine.processEvent(deviceId, orgId, {
      event_type: 'UNUSUAL_LOCATION',
      details: 'Offshore login from Frankfurt, Germany',
      severity: 'HIGH',
      timestamp: new Date().toISOString()
    });

    // 3. Privilege escalation
    const result = endpointDetectionEngine.processEvent(deviceId, orgId, {
      event_type: 'PRIVILEGE_ESCALATION',
      details: 'Unauthorized privilege escalation: process spawned with SeDebugPrivilege (demo_suspicious)',
      severity: 'CRITICAL',
      timestamp: new Date().toISOString()
    });

    assert.ok(result);
    assert.strictEqual(result.status, 'Compromised');
    assert.strictEqual(result.severity, 'CRITICAL');
    assert.ok(result.confidence >= 90, 'Multi-stage detection confidence must be >= 90%');
    assert.ok(result.matchedRules.length >= 2, 'Should match multiple correlation rules');

    // Check device state in DB
    const device = endpointDb.getDeviceById(deviceId)!;
    assert.strictEqual(device.status, 'Compromised');
    assert.ok(device.risk >= 90, 'Device risk must escalate to critical band');

    // Check incident created deterministically
    assert.strictEqual(result.incidentId, 'inc-endpoint-devbank02');
    const inc = db.incidents.find((i) => i.id === result.incidentId);
    assert.ok(inc, 'Incident must be recorded in SOC registry');
    assert.strictEqual(inc.status, 'Detected');

    // Check associated response actions
    const killAction = db.responseActions.find((a) => a.id === 'act-kill-dev-bank-02');
    assert.ok(killAction, 'kill_process action must be auto-generated');
    assert.strictEqual(killAction.status, 'Pending');
  });

  test('Produces deterministic IDs without Math.random', () => {
    const deviceId = 'DEV-HOSP-01';
    const orgId = 'org-2';

    const res1 = endpointDetectionEngine.processEvent(deviceId, orgId, {
      event_type: 'PRIVILEGE_ESCALATION',
      details: 'Root escalation test',
      severity: 'CRITICAL',
      timestamp: new Date().toISOString()
    });

    assert.ok(res1);
    assert.strictEqual(res1.incidentId, 'inc-endpoint-devhosp01');
  });
});

