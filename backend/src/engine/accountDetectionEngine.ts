import { db } from '../models/db.js';
import { endpointDb, UserRecord, LoginAttemptRecord } from '../db/endpointDb.js';
import { calculateOrganizationRisk } from './riskEngine.js';
import { wsHub } from '../ws/wsHub.js';

export interface AccountFactorContribution {
  id: string;
  category: 'Authentication' | 'Device Security' | 'Geographic Velocity' | 'Privilege' | 'Data Access';
  points: number;
  explanation: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
}

export interface AccountAlert {
  id: string;
  userId: string;
  userEmail: string;
  userName: string;
  orgId: string;
  status: 'New' | 'Investigating' | 'Remediated';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: number;
  title: string;
  summary: string;
  matchedRules: string[];
  factorContributions: AccountFactorContribution[];
  accountRiskScore: number;
  recommendedFixes: string[];
  timestamp: string;
  remediatedAt?: string | null;
  remediatedBy?: string | null;
}

export interface AccountEvent {
  eventType: 'FAILED_LOGIN' | 'SUCCESSFUL_LOGIN' | 'NEW_DEVICE' | 'UNUSUAL_LOCATION' | 'PRIVILEGE_ESCALATION' | 'LARGE_DATA_TRANSFER';
  ipAddress?: string;
  deviceFingerprint?: string;
  location?: string;
  details?: string;
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  timestamp: number;
}

class AccountDetectionEngine {
  // Sliding 60-second event window per user
  private userWindows = new Map<string, AccountEvent[]>();

  // In-memory cache of latest alerts per user for instant lookups
  public activeAlerts = new Map<string, AccountAlert>();

  /**
   * Process a live login attempt from the login endpoint.
   * If real consecutive failures or anomalies occur, generate an alert.
   */
  public processLoginAttempt(attempt: LoginAttemptRecord): AccountAlert | null {
    const user = attempt.user_id ? endpointDb.getUserById(attempt.user_id) : endpointDb.getUserByEmail(attempt.email);
    if (!user) return null;

    const eventType: AccountEvent['eventType'] = attempt.success === 1 ? 'SUCCESSFUL_LOGIN' : 'FAILED_LOGIN';
    const now = new Date(attempt.timestamp).getTime() || Date.now();

    const event: AccountEvent = {
      eventType,
      ipAddress: attempt.ip_address,
      deviceFingerprint: attempt.device_fingerprint,
      location: attempt.location,
      details: attempt.failure_reason || 'Interactive authentication attempt',
      severity: attempt.success === 1 ? 'LOW' : 'HIGH',
      timestamp: now
    };

    return this.recordEventAndEvaluate(user, event);
  }

  /**
   * Record an arbitrary account event and evaluate rules against the 60s sliding window.
   */
  public recordEventAndEvaluate(user: UserRecord, event: AccountEvent): AccountAlert | null {
    const now = Date.now();
    const eventTime = event.timestamp || now;

    if (!this.userWindows.has(user.id)) {
      this.userWindows.set(user.id, []);
    }
    const window = this.userWindows.get(user.id)!;

    // Append event
    window.push({
      ...event,
      timestamp: eventTime
    });

    // Prune events older than 60 seconds
    const windowStart = now - 60000;
    while (window.length > 0 && window[0].timestamp < windowStart) {
      window.shift();
    }

    // Evaluate the 6 Account Attack Rules
    const matchedRules: string[] = [];
    const factorContributions: AccountFactorContribution[] = [];
    let confidenceSum = 0;
    let ruleCount = 0;

    // Rule 1: Rapid Failed Logins Anomaly (Credential Stuffing / Brute Force)
    const failedLogins = window.filter((e) => e.eventType === 'FAILED_LOGIN');
    if (failedLogins.length >= 5) {
      matchedRules.push(`RULE-AUTH-01: Rapid Failed Logins Streak (${failedLogins.length} attempts in 60s window)`);
      factorContributions.push({
        id: 'fc-auth-01',
        category: 'Authentication',
        points: Math.min(32, 16 + failedLogins.length * 2),
        explanation: `${failedLogins.length} repeated failed authentications detected in 60 seconds, indicating automated credential stuffing / dictionary brute-force.`,
        severity: 'HIGH'
      });
      confidenceSum += 88;
      ruleCount++;
    }

    // Rule 2: Successful Login After Multiple Failures
    const successEvents = window.filter((e) => e.eventType === 'SUCCESSFUL_LOGIN');
    if (failedLogins.length >= 3 && successEvents.length >= 1) {
      matchedRules.push('RULE-AUTH-02: Successful Authentication Directly Following Brute-Force Streak');
      factorContributions.push({
        id: 'fc-auth-02',
        category: 'Authentication',
        points: 26,
        explanation: 'Attacker successfully obtained access after repeated credential failures, indicating probable credential compromise.',
        severity: 'CRITICAL'
      });
      confidenceSum += 92;
      ruleCount++;
    }

    // Rule 3: Unrecognized Device Fingerprint
    const newDevice = window.find((e) => e.eventType === 'NEW_DEVICE' || (e.deviceFingerprint && e.deviceFingerprint.includes('Python')));
    if (newDevice) {
      matchedRules.push('RULE-DEV-03: Sign-In From Unrecognized Hardware / Browser Fingerprint');
      factorContributions.push({
        id: 'fc-dev-03',
        category: 'Device Security',
        points: 18,
        explanation: `Device fingerprint '${newDevice.deviceFingerprint || 'Unknown Client'}' is not recognized in user baseline profile.`,
        severity: 'MEDIUM'
      });
      confidenceSum += 84;
      ruleCount++;
    }

    // Rule 4: Anomalous Geographic Location / Velocity
    const unusualGeo = window.find((e) => e.eventType === 'UNUSUAL_LOCATION' || (e.location && !e.location.includes('New York') && !e.location.includes('US')));
    if (unusualGeo) {
      matchedRules.push(`RULE-GEO-04: Anomalous Geographic Velocity (${unusualGeo.location || 'Foreign Location'})`);
      factorContributions.push({
        id: 'fc-geo-04',
        category: 'Geographic Velocity',
        points: 22,
        explanation: `Authentication origin '${unusualGeo.location || 'Foreign Geolocation'}' deviates from verified domestic baseline (New York, US).`,
        severity: 'HIGH'
      });
      confidenceSum += 86;
      ruleCount++;
    }

    // Rule 5: Unauthorized Privilege Escalation
    const privEsc = window.find((e) => e.eventType === 'PRIVILEGE_ESCALATION');
    if (privEsc) {
      matchedRules.push('RULE-PRIV-05: Unauthorized Administrative Privilege Escalation Attempt');
      factorContributions.push({
        id: 'fc-priv-05',
        category: 'Privilege',
        points: 28,
        explanation: 'Identity attempted administrative privilege elevation to access restricted multi-tenant configurations.',
        severity: 'CRITICAL'
      });
      confidenceSum += 96;
      ruleCount++;
    }

    // Rule 6: Anomalous Large Data Transfer / High-Volume Access
    const largeData = window.find((e) => e.eventType === 'LARGE_DATA_TRANSFER');
    if (largeData) {
      matchedRules.push('RULE-DATA-06: High-Volume Sensitive Data Egress Anomaly (4.5 GB)');
      factorContributions.push({
        id: 'fc-data-06',
        category: 'Data Access',
        points: 24,
        explanation: 'Abnormal batch export of 5,000+ sensitive records detected, exceeding 95th percentile baseline transfer threshold.',
        severity: 'CRITICAL'
      });
      confidenceSum += 94;
      ruleCount++;
    }

    // If no rules matched, no alert
    if (matchedRules.length === 0) {
      return null;
    }

    const confidence = Math.round(confidenceSum / ruleCount);
    const isCritical = factorContributions.some((fc) => fc.severity === 'CRITICAL') || matchedRules.length >= 2;
    const severity: AccountAlert['severity'] = isCritical ? 'CRITICAL' : 'HIGH';

    // Deterministic Alert ID: e.g. alt-usr-bank-alice (No Math.random!)
    const cleanId = user.id.toLowerCase().replace(/[^a-z0-9]/g, '');
    const alertId = `alt-${cleanId}`;

    const totalPoints = factorContributions.reduce((acc, fc) => acc + fc.points, 0);
    const accountRiskScore = Math.min(99, Math.max(50, 40 + totalPoints));

    const alert: AccountAlert = {
      id: alertId,
      userId: user.id,
      userEmail: user.email,
      userName: user.name,
      orgId: user.org_id,
      status: 'New',
      severity,
      confidence,
      title: isCritical
        ? `HOSTILE ACCOUNT COMPROMISE & ELEVATION DETECTED: ${user.name.toUpperCase()}`
        : `SUSPICIOUS AUTHENTICATION ANOMALY ON ${user.name.toUpperCase()}`,
      summary: `Correlated ${matchedRules.length} account-level attack pattern(s) across recent 60-second sliding telemetry window.`,
      matchedRules,
      factorContributions,
      accountRiskScore,
      recommendedFixes: [
        'lock_account',
        'force_logout',
        'force_password_reset',
        'require_mfa',
        'block_ip_device'
      ],
      timestamp: new Date().toISOString()
    };

    // 1. Save Alert to SQLite
    endpointDb.saveAccountAlert({
      id: alert.id,
      user_id: alert.userId,
      user_email: alert.userEmail,
      user_name: alert.userName,
      org_id: alert.orgId,
      status: alert.status,
      severity: alert.severity,
      confidence: alert.confidence,
      title: alert.title,
      summary: alert.summary,
      matched_rules: JSON.stringify(alert.matchedRules),
      factor_contributions: JSON.stringify(alert.factorContributions),
      account_risk_score: alert.accountRiskScore,
      recommended_fixes: JSON.stringify(alert.recommendedFixes),
      timestamp: alert.timestamp,
      remediated_at: null,
      remediated_by: null
    });

    this.activeAlerts.set(alert.userId, alert);

    // 2. Recompute Organization Risk through riskEngine
    const org = db.organizations[user.org_id] || db.getActiveOrganization();
    org.riskBreakdown.authentication = Math.min(99, org.riskBreakdown.authentication + 18);
    org.riskBreakdown.userRisk = Math.min(99, org.riskBreakdown.userRisk + 24);
    org.riskTrend = 'RISING';

    const calculatedRisk = calculateOrganizationRisk(org, 3);
    org.riskScore = calculatedRisk.overallRiskScore;

    // 3. Append to Audit Log
    endpointDb.appendAudit(
      'AccountDetectionEngine',
      user.org_id,
      'ACCOUNT_ATTACK_DETECTED',
      `Alert ${alert.id} generated for ${user.email} (${alert.severity}, ${alert.confidence}% confidence). User risk: ${accountRiskScore}, Org risk: ${org.riskScore}. Rules: ${matchedRules.join(' | ')}`
    );

    // 4. Real-Time WebSocket Broadcast to Admins
    wsHub.broadcastToAdmins(user.org_id, {
      type: 'ACCOUNT_ALERT',
      alert,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        status: user.status,
        accountRisk: accountRiskScore
      },
      updatedOrgRisk: org.riskScore,
      timestamp: alert.timestamp
    });

    console.log(`🚨 [AccountDetectionEngine] Alert dispatched for ${user.email}: ${alert.title} (Confidence: ${confidence}%, Risk: ${accountRiskScore})`);
    return alert;
  }

  /**
   * SIMULATION-ONLY: Inject an attack sequence on a target user.
   * Produces deterministic alert and waterfall breakdown.
   */
  public simulateAccountAttack(userId: string): AccountAlert {
    const user = endpointDb.getUserById(userId);
    if (!user) {
      throw new Error(`User with ID ${userId} not found.`);
    }

    const now = Date.now();
    const attackerIp = '198.51.100.42';
    const attackerDevice = 'Python-Requests/2.31 (Adversary Script)';
    const foreignLocation = 'Frankfurt, Germany';

    // Clear previous window for clean deterministic simulation
    this.userWindows.set(user.id, []);

    // 1. Inject 5 failed login attempts
    for (let i = 1; i <= 5; i++) {
      const attemptId = `att-sim-${user.id}-${i}`;
      const ts = new Date(now - (60 - i * 5) * 1000).toISOString();
      const loginAttempt: LoginAttemptRecord = {
        id: attemptId,
        user_id: user.id,
        email: user.email,
        org_id: user.org_id,
        success: 0,
        ip_address: attackerIp,
        device_fingerprint: attackerDevice,
        location: foreignLocation,
        failure_reason: 'INCORRECT_PASSWORD',
        timestamp: ts
      };
      endpointDb.recordLoginAttempt(loginAttempt);
      this.userWindows.get(user.id)!.push({
        eventType: 'FAILED_LOGIN',
        ipAddress: attackerIp,
        deviceFingerprint: attackerDevice,
        location: foreignLocation,
        details: 'Simulated brute-force attempt',
        severity: 'HIGH',
        timestamp: now - (60 - i * 5) * 1000
      });
    }

    // 2. Inject 1 successful login directly after failures
    const successAttemptId = `att-sim-${user.id}-success`;
    const successTs = new Date(now - 15000).toISOString();
    endpointDb.recordLoginAttempt({
      id: successAttemptId,
      user_id: user.id,
      email: user.email,
      org_id: user.org_id,
      success: 1,
      ip_address: attackerIp,
      device_fingerprint: attackerDevice,
      location: foreignLocation,
      failure_reason: null,
      timestamp: successTs
    });
    this.userWindows.get(user.id)!.push({
      eventType: 'SUCCESSFUL_LOGIN',
      ipAddress: attackerIp,
      deviceFingerprint: attackerDevice,
      location: foreignLocation,
      details: 'Simulated cracked credential login',
      severity: 'CRITICAL',
      timestamp: now - 15000
    });

    // 3. Inject new device event
    this.userWindows.get(user.id)!.push({
      eventType: 'NEW_DEVICE',
      deviceFingerprint: attackerDevice,
      details: 'Unrecognized automation client',
      timestamp: now - 14000
    });

    // 4. Inject unusual location event
    this.userWindows.get(user.id)!.push({
      eventType: 'UNUSUAL_LOCATION',
      location: foreignLocation,
      details: 'Offshore IP anomaly',
      timestamp: now - 13000
    });

    // 5. Inject privilege escalation event
    this.userWindows.get(user.id)!.push({
      eventType: 'PRIVILEGE_ESCALATION',
      details: 'Attempted sudo / role promotion to ADMIN',
      severity: 'CRITICAL',
      timestamp: now - 10000
    });

    // 6. Inject large data egress event
    const finalEvent: AccountEvent = {
      eventType: 'LARGE_DATA_TRANSFER',
      details: 'Bulk download of customer financial tables (4.5 GB)',
      severity: 'CRITICAL',
      timestamp: now - 5000
    };

    // Run evaluation
    const alert = this.recordEventAndEvaluate(user, finalEvent);
    if (!alert) {
      throw new Error('Simulation failed to trigger alert rules.');
    }

    return alert;
  }

  /**
   * Mark alert as Remediated (called by Phase 4 Admin Remote Fix).
   * Drops org risk and restores security indicators.
   */
  public remediateAlert(alertId: string, adminActor: string): { alert: AccountAlert; updatedOrgRisk: number } | null {
    const record = endpointDb.getAccountAlertById(alertId);
    if (!record) return null;

    endpointDb.updateAccountAlertStatus(alertId, 'Remediated', adminActor);

    // De-escalate Org Risk
    const org = db.organizations[record.org_id] || db.getActiveOrganization();
    org.riskBreakdown.authentication = Math.max(25, org.riskBreakdown.authentication - 20);
    org.riskBreakdown.userRisk = Math.max(20, org.riskBreakdown.userRisk - 25);
    org.riskTrend = 'FALLING';

    const activeAlerts = endpointDb.getAccountAlertsByOrg(record.org_id).filter((a) => a.status !== 'Remediated');
    const newRisk = calculateOrganizationRisk(org, activeAlerts.length);
    org.riskScore = newRisk.overallRiskScore;

    const updatedAlert: AccountAlert = {
      id: record.id,
      userId: record.user_id,
      userEmail: record.user_email,
      userName: record.user_name,
      orgId: record.org_id,
      status: 'Remediated',
      severity: 'LOW',
      confidence: record.confidence,
      title: `[REMEDIATED] ${record.title}`,
      summary: `Remediated by administrator (${adminActor}). Account secured and risk neutralized.`,
      matchedRules: JSON.parse(record.matched_rules || '[]'),
      factorContributions: JSON.parse(record.factor_contributions || '[]'),
      accountRiskScore: 18,
      recommendedFixes: [],
      timestamp: record.timestamp,
      remediatedAt: new Date().toISOString(),
      remediatedBy: adminActor
    };

    this.activeAlerts.set(record.user_id, updatedAlert);

    // Real-Time WebSocket broadcast of remediation
    wsHub.broadcastToAdmins(record.org_id, {
      type: 'ACCOUNT_REMEDIATED',
      alert: updatedAlert,
      user: {
        id: record.user_id,
        email: record.user_email,
        name: record.user_name,
        status: 'active',
        accountRisk: 18
      },
      updatedOrgRisk: org.riskScore,
      timestamp: updatedAlert.remediatedAt
    });

    return { alert: updatedAlert, updatedOrgRisk: org.riskScore };
  }

  /**
   * Reset in-memory alerts and sliding windows for clean baseline demo reproducibility.
   */
  public clearAllAlerts() {
    this.activeAlerts.clear();
    this.userWindows.clear();
  }
}

export const accountDetectionEngine = new AccountDetectionEngine();

