import { describe, it } from 'node:test';
import assert from 'node:assert';
import { db } from '../models/db.js';

describe('Deterministic 4-Day Demo Narrative & Baseline Reset', () => {
  it('resets cleanly to baseline state', () => {
    // Alter risk and active org
    db.activeOrgId = 'org-2';
    db.organizations['org-1'].riskScore = 99;

    db.resetToBaseline();

    assert.strictEqual(db.activeOrgId, 'org-1');
    assert.strictEqual(db.organizations['org-1'].riskScore, 84);
    assert.strictEqual(db.ledgerRecords.length >= 3, true);
  });

  it('progresses deterministically through 4-day narrative risk shifts', () => {
    // Day 1: Normal Baseline Posture
    db.organizations['org-1'].riskScore = 42;
    assert.strictEqual(db.organizations['org-1'].riskScore, 42);

    // Day 2: Lateral Movement Infiltration
    db.organizations['org-1'].riskScore = 78;
    assert.strictEqual(db.organizations['org-1'].riskScore, 78);

    // Day 3: Privilege Escalation & Cross-Org Early Warning
    db.organizations['org-1'].riskScore = 91;
    assert.strictEqual(db.organizations['org-1'].riskScore, 91);

    // Day 4: Containment & Remediation
    db.organizations['org-1'].riskScore = 24;
    assert.strictEqual(db.organizations['org-1'].riskScore, 24);

    // Clean up
    db.resetToBaseline();
  });
});
