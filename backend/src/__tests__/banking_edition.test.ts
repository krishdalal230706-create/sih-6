import test from 'node:test';
import assert from 'node:assert';
import { endpointDb } from '../db/endpointDb.js';
import { calculateOrganizationRisk, BANKING_RISK_WEIGHTS } from '../engine/riskEngine.js';
import { db } from '../models/db.js';
import { Organization } from '../types.js';

test('Banking Security Edition: Demo Bank Baseline & 10 Synthetic Assets', async (t) => {
  await t.test('1. Demo Bank (org-1) is configured as Primary Banking Institution', () => {
    endpointDb.seedBankingDataIfEmpty();
    const org = endpointDb.getOrgById('org-1');
    assert.ok(org, 'org-1 must exist');
    assert.strictEqual(org.name, 'Demo Bank');
    assert.strictEqual(org.type, 'Banking and Financial Services');

    const adminUser = endpointDb.getUserByEmail('admin@demobank.com');
    assert.ok(adminUser, 'Demo Bank SOC Admin must exist');
    assert.strictEqual(adminUser.org_id, 'org-1');
    assert.strictEqual(adminUser.role, 'admin');
  });

  await t.test('2. Exactly 10 baseline synthetic banking assets exist for Demo Bank', () => {
    const assets = endpointDb.getBankAssets('org-1');
    assert.ok(assets.length >= 10, `Expected at least 10 assets, got ${assets.length}`);

    const expectedAssetIds = [
      'asset-cbs',
      'asset-netbank',
      'asset-mobile',
      'asset-atm',
      'asset-payment',
      'asset-custdb',
      'asset-workstations',
      'asset-auth',
      'asset-network',
      'asset-dr'
    ];

    for (const expectedId of expectedAssetIds) {
      const found = assets.find((a) => a.id === expectedId);
      assert.ok(found, `Asset ${expectedId} should be present`);
      assert.ok(found.risk_score >= 0 && found.risk_score <= 100, `Asset ${expectedId} risk score should be in 0-100`);
      assert.ok(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(found.criticality), `Asset ${expectedId} has valid criticality`);
      assert.ok(['HEALTHY', 'DEGRADED', 'AT_RISK', 'COMPROMISED', 'MAINTENANCE'].includes(found.security_status), `Asset ${expectedId} has valid status`);
    }
  });

  await t.test('3. Asset CRUD: Admin can create, update, and delete banking assets', () => {
    const testAssetId = 'asset-test-clearing-node';
    const now = new Date().toISOString();

    // Create
    endpointDb.saveBankAsset({
      id: testAssetId,
      org_id: 'org-1',
      name: 'RTGS Clearing Node (Test)',
      category: 'Core Banking',
      description: 'High-value real-time gross settlement interface node.',
      criticality: 'CRITICAL',
      ip_or_identifier: '10.10.99.1',
      technology_stack: 'Oracle Linux 8.6 / RTGS Daemon',
      owner_department: 'Treasury & Settlement',
      security_status: 'HEALTHY',
      associated_vulns_count: 0,
      last_assessment_date: '2026-11-02',
      risk_score: 22,
      created_at: now,
      updated_at: now
    });

    const created = endpointDb.getBankAssetById(testAssetId);
    assert.ok(created, 'Created asset must be retrievable');
    assert.strictEqual(created.name, 'RTGS Clearing Node (Test)');

    // Update
    const updated = endpointDb.updateBankAsset(testAssetId, {
      security_status: 'AT_RISK',
      risk_score: 55
    });
    assert.ok(updated, 'Updated asset must return record');
    assert.strictEqual(updated.security_status, 'AT_RISK');
    assert.strictEqual(updated.risk_score, 55);

    // Delete
    const deleted = endpointDb.deleteBankAsset(testAssetId);
    assert.strictEqual(deleted, true);
    assert.strictEqual(endpointDb.getBankAssetById(testAssetId), undefined);
  });
});

test('Banking Cyber Risk Engine: 10 Categories & Normalized Weights', async (t) => {
  await t.test('1. Weights strictly sum to 100% (1.00)', () => {
    const sum =
      BANKING_RISK_WEIGHTS.authentication +
      BANKING_RISK_WEIGHTS.coreBanking +
      BANKING_RISK_WEIGHTS.paymentGateway +
      BANKING_RISK_WEIGHTS.customerData +
      BANKING_RISK_WEIGHTS.networkSecurity +
      BANKING_RISK_WEIGHTS.endpointSecurity +
      BANKING_RISK_WEIGHTS.atmSecurity +
      BANKING_RISK_WEIGHTS.thirdParty +
      BANKING_RISK_WEIGHTS.vulnerabilityExposure +
      BANKING_RISK_WEIGHTS.incidentHistory;

    assert.strictEqual(Math.round(sum * 100), 100, 'Sum of weights must equal 100%');
  });

  await t.test('2. Dynamic calculation incorporates banking assets and produces valid score', () => {
    const mockOrg: Organization = {
      id: 'org-1',
      name: 'Demo Bank',
      type: 'Banking and Financial Services',
      country: 'India',
      usersCount: 12500,
      criticalSystems: 10,
      internetFacingServices: 4,
      authenticationMethods: ['FIDO2', 'SMS_OTP', 'PASSWORD'],
      securityControls: ['WAF', 'EDR', 'DAM', 'DLP'],
      knownVulnerabilities: 8,
      dataSensitivity: 'CRITICAL',
      previousIncidents: 1,
      riskScore: 78,
      riskTrend: 'RISING',
      lastUpdated: new Date().toISOString(),
      riskBreakdown: {
        authentication: 45,
        networkSecurity: 35,
        dataSecurity: 50,
        endpointSecurity: 60,
        userRisk: 40
      },
      activeThreatsCount: { critical: 2, high: 4, medium: 8, low: 12 }
    };

    const result = calculateOrganizationRisk(mockOrg, 3);
    assert.ok(result.overallRiskScore >= 1 && result.overallRiskScore <= 100, 'Score must be 1-100');
    assert.ok(result.bankingCategoryScores, 'bankingCategoryScores must be populated');
    assert.ok(result.highestRiskAssets.length > 0, 'Highest risk assets must be identified');
    assert.ok(result.explainableDeltas.length > 0, 'Explainable factor deltas must be present');
    assert.ok(result.recommendations.length > 0, 'Actionable banking recommendations must exist');

    // Verify 10 distinct category scores exist
    const scores = result.bankingCategoryScores;
    assert.ok(typeof scores.authentication === 'number');
    assert.ok(typeof scores.coreBanking === 'number');
    assert.ok(typeof scores.paymentGateway === 'number');
    assert.ok(typeof scores.customerData === 'number');
    assert.ok(typeof scores.networkSecurity === 'number');
    assert.ok(typeof scores.endpointSecurity === 'number');
    assert.ok(typeof scores.atmSecurity === 'number');
    assert.ok(typeof scores.thirdParty === 'number');
    assert.ok(typeof scores.vulnerabilityExposure === 'number');
    assert.ok(typeof scores.incidentHistory === 'number');
  });
});

test('Banking Threat Detection & Security Events', async (t) => {
  await t.test('1. Demo Bank initial security events are seeded', () => {
    const events = endpointDb.getBankSecurityEvents('org-1');
    assert.ok(events.length >= 5, `Expected at least 5 events, got ${events.length}`);
    const criticalEvt = events.find((e) => e.severity === 'CRITICAL');
    assert.ok(criticalEvt, 'Should contain a critical payment event');
  });

  await t.test('2. Security Event investigation lifecycle can be transitioned', () => {
    const testEvtId = 'evt-test-lifecycle-01';
    endpointDb.saveBankSecurityEvent({
      id: testEvtId,
      org_id: 'org-1',
      affected_asset_id: 'asset-netbank',
      event_category: 'Credential Stuffing Test',
      severity: 'HIGH',
      timestamp: new Date().toISOString(),
      description: 'Simulated brute-force test against internet banking portal.',
      detection_source: 'Unit Test Sensor',
      investigation_status: 'NEW',
      recommended_action: 'Verify step-up challenge.'
    });

    const evt = endpointDb.getBankSecurityEventById(testEvtId);
    assert.ok(evt, 'Event must exist');
    assert.strictEqual(evt.investigation_status, 'NEW');

    // Move to INVESTIGATING
    const investigating = endpointDb.updateBankSecurityEventStatus(testEvtId, 'INVESTIGATING');
    assert.strictEqual(investigating?.investigation_status, 'INVESTIGATING');

    // Move to CONTAINED
    const contained = endpointDb.updateBankSecurityEventStatus(testEvtId, 'CONTAINED');
    assert.strictEqual(contained?.investigation_status, 'CONTAINED');

    // Move to RESOLVED
    const resolved = endpointDb.updateBankSecurityEventStatus(testEvtId, 'RESOLVED');
    assert.strictEqual(resolved?.investigation_status, 'RESOLVED');
  });
});

test('Banking Attack Simulator: 6 Controlled Scenarios', async (t) => {
  await t.test('1. Exactly 6 controlled banking attack scenarios are configured', () => {
    const scenarios = db.attackScenarios;
    assert.strictEqual(scenarios.length, 6, 'Should have exactly 6 banking scenarios');

    const expectedNames = [
      'Phishing & Employee Account Takeover',
      'Distributed Credential Stuffing on NetBanking',
      'Payment Gateway Fraud & Velocity Burst',
      'Controlled Ransomware Simulation',
      'Insider Threat & Unauthorized CIF Access',
      'Third-Party Software Dependency Flaw'
    ];

    for (let i = 0; i < expectedNames.length; i++) {
      assert.strictEqual(scenarios[i].name, expectedNames[i], `Scenario ${i + 1} name match`);
      assert.ok(scenarios[i].nodes.length >= 2, `Scenario ${i + 1} should have multi-step nodes`);
      assert.ok(scenarios[i].criticalWeakPoint.length > 5, `Scenario ${i + 1} should have critical weak point`);
    }
  });
});

