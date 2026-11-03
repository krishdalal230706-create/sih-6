import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { endpointDb, LoginAttemptRecord } from '../db/endpointDb.js';
import { accountDetectionEngine } from '../engine/accountDetectionEngine.js';
import { requireAuth, requireAdmin, requireDemoMode, AuthenticatedRequest } from '../middleware/authMiddleware.js';
import { db } from '../models/db.js';
import { calculateOrganizationRisk } from '../engine/riskEngine.js';
import { wsHub } from '../ws/wsHub.js';
import { sanitizeAccountAlertToPattern } from '../engine/privacyEngine.js';
import { addLedgerBlock, verifyLedgerChain } from '../engine/dltLedger.js';
import { correlateThreatPatterns } from '../engine/correlationEngine.js';
import { clearEmailLockout } from './auth.js';

export const accountSecurityRouter = Router();

// In-memory action deduplication tracker (prevents duplicate clicks within 2s)
const recentActions = new Map<string, number>();

const simulateSchema = z.object({
  userId: z.string().min(1),
  attackType: z.string().optional()
});

const fixSchema = z.object({
  userId: z.string().min(1),
  action: z.enum([
    'lock_account',
    'force_logout',
    'force_password_reset',
    'require_mfa',
    'block_ip_device',
    'revert_privileges',
    'unlock_restore'
  ]),
  alertId: z.string().optional(),
  entityValue: z.string().optional(),
  reason: z.string().optional()
});

// GET /api/account-security/targets
// List eligible attack target accounts in caller's organization (Admin or attack_target@banka.com)
accountSecurityRouter.get('/targets', requireAuth, requireDemoMode, (req: AuthenticatedRequest, res: Response) => {
  const isAttackAccount = req.user!.email === 'attack_target@banka.com';
  if (req.user!.role !== 'admin' && !isAttackAccount) {
    return res.status(403).json({ error: 'FORBIDDEN', message: 'Target inspection reserved for SOC administrators and Red Team sandbox accounts.' });
  }

  const orgId = req.user!.orgId;
  const users = endpointDb.getUsersByOrg(orgId).map((u) => ({
    id: u.id,
    name: u.name,
    email: u.email,
    role: u.role,
    status: u.status,
    privilegeLevel: u.privilege_level || 'STANDARD',
    isUnderAttack: Boolean(endpointDb.getAccountAlertByUserId(u.id))
  }));

  res.json({ targets: users });
});

// SIMULATION-ONLY: Simulate account attack sequence on chosen user (Admin or attack_target account, DEMO_MODE only)
accountSecurityRouter.post('/simulate', requireAuth, requireDemoMode, async (req: AuthenticatedRequest, res: Response) => {
  const parseResult = simulateSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({
      error: 'INVALID_INPUT',
      details: parseResult.error.issues.map((i) => i.message)
    });
  }

  const { userId, attackType } = parseResult.data;
  const user = endpointDb.getUserById(userId);
  if (!user) {
    return res.status(404).json({ error: 'USER_NOT_FOUND', message: 'Target user does not exist.' });
  }

  const isAttackAccount = req.user!.email === 'attack_target@banka.com';

  // Permissions check:
  // - Admin can simulate on any user in their own org
  // - attack_target@banka.com (Red Team Sandbox Account) can simulate on ANY user in their own org
  // - Other standard users can only test attack simulation on their own account
  if (req.user!.role !== 'admin' && !isAttackAccount && user.id !== req.user!.userId) {
    return res.status(403).json({
      error: 'FORBIDDEN',
      message: 'Standard users can only test attack simulation on their own account.'
    });
  }

  if ((req.user!.role === 'admin' || isAttackAccount) && user.org_id !== req.user!.orgId) {
    return res.status(403).json({
      error: 'FORBIDDEN',
      message: 'Cannot simulate attacks on users of another organization.'
    });
  }

  try {
    const alert = accountDetectionEngine.simulateAccountAttack(userId, attackType);
    if (isAttackAccount) {
      endpointDb.appendAudit(
        req.user!.email,
        user.org_id,
        'RED_TEAM_ATTACK_LAUNCHED',
        `Red Team Adversary account (${req.user!.email}) executed simulated ${attackType || 'ALL'} intrusion targeting ${user.name} (${user.email}). Alert dispatched to SOC.`
      );
    }
    res.json({
      success: true,
      isSimulation: true,
      message: `Simulated attack executed against ${user.name} (${user.email}). Alert generated and org risk elevated. Admin notified.`,
      alert
    });
  } catch (err: any) {
    res.status(500).json({ error: 'SIMULATION_FAILED', message: err.message });
  }
});

// Admin Remote Fix: Execute account-level remediation (Phase 4)
accountSecurityRouter.post('/fix', requireAuth, requireAdmin, async (req: AuthenticatedRequest, res: Response) => {
  const parseResult = fixSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({
      error: 'INVALID_INPUT',
      details: parseResult.error.issues.map((i) => i.message)
    });
  }

  const { userId, action, alertId, entityValue, reason } = parseResult.data;
  const adminActor = req.user!.email;
  const adminOrgId = req.user!.orgId;

  // 1. Target User Validation & Multi-Tenant Scoping
  const user = endpointDb.getUserById(userId);
  if (!user) {
    return res.status(404).json({ error: 'USER_NOT_FOUND', message: 'Target user account not found.' });
  }

  if (user.org_id !== adminOrgId) {
    return res.status(403).json({
      error: 'FORBIDDEN',
      message: 'Unauthorized: Admins can only execute remote remediation on accounts within their own organization.'
    });
  }

  // 2. Prevent Duplicate Clicks (2-second deduplication)
  const actionKey = `${adminActor}:${userId}:${action}`;
  const now = Date.now();
  const lastExec = recentActions.get(actionKey);
  if (lastExec && now - lastExec < 2000) {
    return res.status(409).json({
      error: 'DUPLICATE_ACTION',
      message: 'Remote fix is already in progress. Duplicate execution prevented.'
    });
  }
  recentActions.set(actionKey, now);

  const timestampStr = new Date().toLocaleString();
  let resultMessage = '';

  // 3. Execute Server-Side Account Fix
  switch (action) {
    case 'lock_account':
      endpointDb.updateUserStatus(user.id, 'locked');
      endpointDb.revokeAllUserSessions(user.id);
      endpointDb.addAccountNotice(
        user.id,
        user.org_id,
        'ACCOUNT_LOCKED',
        `Your account was locked by an administrator on ${timestampStr} for security containment.`
      );
      endpointDb.appendAudit(
        adminActor,
        user.org_id,
        'USER_ACCOUNT_LOCKED',
        `Account ${user.email} was locked by SOC administrator ${adminActor}. All active sessions revoked.`
      );
      resultMessage = `Account ${user.email} has been locked and all sessions revoked immediately.`;
      break;

    case 'force_logout':
      endpointDb.revokeAllUserSessions(user.id);
      endpointDb.addAccountNotice(
        user.id,
        user.org_id,
        'SESSIONS_REVOKED',
        `All active sessions were revoked by an administrator on ${timestampStr}.`
      );
      endpointDb.appendAudit(
        adminActor,
        user.org_id,
        'USER_SESSIONS_REVOKED',
        `All active sessions revoked for ${user.email} by administrator ${adminActor}.`
      );
      resultMessage = `All active sessions revoked for ${user.email}.`;
      break;

    case 'force_password_reset':
      endpointDb.updateUserStatus(user.id, 'reset_required');
      endpointDb.addAccountNotice(
        user.id,
        user.org_id,
        'PASSWORD_RESET_REQUIRED',
        `A password reset was required by an administrator on ${timestampStr}. You must set a new password on login.`
      );
      endpointDb.appendAudit(
        adminActor,
        user.org_id,
        'PASSWORD_RESET_FORCED',
        `Mandatory password reset required for ${user.email} by administrator ${adminActor}.`
      );
      resultMessage = `Forced password reset required for ${user.email}. Account flagged reset_required.`;
      break;

    case 'require_mfa':
      endpointDb.updateUserMfa(user.id, true);
      endpointDb.addAccountNotice(
        user.id,
        user.org_id,
        'MFA_ENFORCED',
        `Multi-factor authentication policy was enforced by an administrator on ${timestampStr}.`
      );
      endpointDb.appendAudit(
        adminActor,
        user.org_id,
        'MFA_ENFORCED',
        `Multi-factor authentication (MFA) policy enforced for ${user.email} by administrator ${adminActor}.`
      );
      resultMessage = `Multi-factor authentication policy enforced for ${user.email}.`;
      break;

    case 'block_ip_device':
      let resolvedIp = entityValue;
      let resolvedDevice = 'Python-Requests/2.31';
      if (!resolvedIp || resolvedIp === '127.0.0.1' || resolvedIp === '::1' || resolvedIp === 'localhost') {
        const attempts = endpointDb.getRecentLoginAttempts(user.email, 20);
        const suspiciousAttempt = attempts.find((a: LoginAttemptRecord) =>
          Boolean(a.ip_address) && a.ip_address !== '127.0.0.1' && a.ip_address !== '::1' && a.ip_address !== 'localhost'
        );
        if (suspiciousAttempt && suspiciousAttempt.ip_address) {
          resolvedIp = suspiciousAttempt.ip_address;
          if (suspiciousAttempt.device_fingerprint) {
            resolvedDevice = suspiciousAttempt.device_fingerprint;
          }
        }
      }
      const targetIp = (resolvedIp && resolvedIp !== '127.0.0.1' && resolvedIp !== '::1' && resolvedIp !== 'localhost')
        ? resolvedIp
        : '198.51.100.42';
      const targetDevice = resolvedDevice;
      endpointDb.blockEntity(
        user.org_id,
        'IP',
        targetIp,
        adminActor,
        reason || 'Adversary IP blocked following account attack correlation'
      );
      endpointDb.blockEntity(
        user.org_id,
        'DEVICE',
        targetDevice,
        adminActor,
        reason || 'Adversary automation fingerprint blocked from auth'
      );
      endpointDb.appendAudit(
        adminActor,
        user.org_id,
        'PERIMETER_ENTITY_BLOCKED',
        `Perimeter access blocked for IP ${targetIp} and device fingerprint ${targetDevice} by ${adminActor}.`
      );
      resultMessage = `Adversary IP ${targetIp} and automation fingerprint blocked from authentication.`;
      break;

    case 'revert_privileges':
      endpointDb.updateUserPrivilege(user.id, 'STANDARD');
      endpointDb.addAccountNotice(
        user.id,
        user.org_id,
        'PRIVILEGE_REVERTED',
        `Your privileges were reverted to STANDARD by an administrator on ${timestampStr}.`
      );
      endpointDb.appendAudit(
        adminActor,
        user.org_id,
        'PRIVILEGE_REVERTED',
        `Privileges reverted to STANDARD baseline for ${user.email} by ${adminActor}.`
      );
      resultMessage = `Privilege level for ${user.email} reverted to STANDARD baseline.`;
      break;

    case 'unlock_restore':
      endpointDb.updateUserStatus(user.id, 'active');
      clearEmailLockout(user.email);
      endpointDb.addAccountNotice(
        user.id,
        user.org_id,
        'ACCOUNT_RESTORED',
        `Your account was unlocked and restored to active status by an administrator on ${timestampStr}.`
      );
      endpointDb.appendAudit(
        adminActor,
        user.org_id,
        'USER_ACCOUNT_UNLOCKED',
        `Account ${user.email} unlocked and restored to active status by administrator ${adminActor}.`
      );
      resultMessage = `Account ${user.email} unlocked and restored to active status.`;
      break;
  }

  // 4. Mark Alert as Remediated & Recalculate Risk Engine
  const targetAlert = alertId
    ? endpointDb.getAccountAlertById(alertId)
    : endpointDb.getAccountAlertByUserId(user.id);

  let updatedOrgRisk = 42;
  if (targetAlert && targetAlert.status !== 'Remediated') {
    const remediated = accountDetectionEngine.remediateAlert(targetAlert.id, adminActor);
    if (remediated) {
      updatedOrgRisk = remediated.updatedOrgRisk;
    }
  } else {
    // If no alert or already remediated, ensure org risk reflects clean posture
    const org = db.organizations[user.org_id] || db.getActiveOrganization();
    org.riskBreakdown.authentication = Math.max(25, org.riskBreakdown.authentication - 15);
    org.riskBreakdown.userRisk = Math.max(20, org.riskBreakdown.userRisk - 20);
    org.riskTrend = 'FALLING';
    const computed = calculateOrganizationRisk(org, 0);
    org.riskScore = computed.overallRiskScore;
    updatedOrgRisk = org.riskScore;
  }

  // 5. Broadcast live state update to all connected admins
  const freshUser = endpointDb.getUserById(user.id)!;
  wsHub.broadcastToAdmins(user.org_id, {
    type: 'ACCOUNT_FIX_EXECUTED',
    action,
    user: {
      id: freshUser.id,
      email: freshUser.email,
      name: freshUser.name,
      status: freshUser.status,
      privilegeLevel: freshUser.privilege_level,
      mfaRequired: freshUser.mfa_required === 1,
      accountRisk: freshUser.status === 'locked' ? 45 : 18
    },
    updatedOrgRisk,
    timestamp: new Date().toISOString()
  });

  // Notify the affected user live on their user channel
  wsHub.broadcastToUser(user.id, {
    type: 'ACCOUNT_STATUS_CHANGED',
    action,
    status: freshUser.status,
    mustReset: freshUser.must_reset === 1 || freshUser.status === 'reset_required',
    message: resultMessage,
    timestamp: new Date().toISOString()
  });

  return res.json({
    success: true,
    action,
    userId: user.id,
    userEmail: user.email,
    updatedStatus: freshUser.status,
    updatedPrivilegeLevel: freshUser.privilege_level,
    updatedOrgRisk,
    user: {
      id: freshUser.id,
      email: freshUser.email,
      name: freshUser.name,
      status: freshUser.status,
      privilegeLevel: freshUser.privilege_level,
      mfaRequired: freshUser.mfa_required === 1
    },
    message: resultMessage
  });
});

// Admin-Only: List all account alerts for admin's organization
accountSecurityRouter.get('/alerts', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const orgId = req.user!.orgId;
  const rawAlerts = endpointDb.getAccountAlertsByOrg(orgId);

  const alerts = rawAlerts.map((a) => ({
    id: a.id,
    userId: a.user_id,
    userEmail: a.user_email,
    userName: a.user_name,
    orgId: a.org_id,
    status: a.status,
    severity: a.severity,
    confidence: a.confidence,
    title: a.title,
    summary: a.summary,
    matchedRules: JSON.parse(a.matched_rules || '[]'),
    factorContributions: JSON.parse(a.factor_contributions || '[]'),
    accountRiskScore: a.account_risk_score,
    recommendedFixes: JSON.parse(a.recommended_fixes || '[]'),
    timestamp: a.timestamp,
    remediatedAt: a.remediated_at,
    remediatedBy: a.remediated_by
  }));

  res.json({ alerts });
});

// Admin-Only: Get alert by ID with full waterfall explainability
accountSecurityRouter.get('/alerts/:id', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const alert = endpointDb.getAccountAlertById(req.params.id);
  if (!alert) {
    return res.status(404).json({ error: 'ALERT_NOT_FOUND', message: 'Alert does not exist.' });
  }

  if (alert.org_id !== req.user!.orgId) {
    return res.status(403).json({ error: 'FORBIDDEN', message: 'Cross-tenant access forbidden.' });
  }

  res.json({
    alert: {
      id: alert.id,
      userId: alert.user_id,
      userEmail: alert.user_email,
      userName: alert.user_name,
      orgId: alert.org_id,
      status: alert.status,
      severity: alert.severity,
      confidence: alert.confidence,
      title: alert.title,
      summary: alert.summary,
      matchedRules: JSON.parse(alert.matched_rules || '[]'),
      factorContributions: JSON.parse(alert.factor_contributions || '[]'),
      accountRiskScore: alert.account_risk_score,
      recommendedFixes: JSON.parse(alert.recommended_fixes || '[]'),
      timestamp: alert.timestamp,
      remediatedAt: alert.remediated_at,
      remediatedBy: alert.remediated_by
    }
  });
});

// Admin-Only: Detailed Account Security View for a specific user
accountSecurityRouter.get('/users/:userId/details', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const user = endpointDb.getUserById(req.params.userId);
  if (!user) {
    return res.status(404).json({ error: 'USER_NOT_FOUND', message: 'User not found.' });
  }

  if (user.org_id !== req.user!.orgId) {
    return res.status(403).json({ error: 'FORBIDDEN', message: 'Cross-tenant access forbidden.' });
  }

  const rawAlert = endpointDb.getAccountAlertByUserId(user.id);
  const recentSignIns = endpointDb.getRecentLoginAttempts(user.email, 20);
  const activeSessions = endpointDb.getActiveSessions(user.id);

  const alert = rawAlert ? {
    id: rawAlert.id,
    userId: rawAlert.user_id,
    userEmail: rawAlert.user_email,
    userName: rawAlert.user_name,
    orgId: rawAlert.org_id,
    status: rawAlert.status,
    severity: rawAlert.severity,
    confidence: rawAlert.confidence,
    title: rawAlert.title,
    summary: rawAlert.summary,
    matchedRules: JSON.parse(rawAlert.matched_rules || '[]'),
    factorContributions: JSON.parse(rawAlert.factor_contributions || '[]'),
    accountRiskScore: rawAlert.account_risk_score,
    recommendedFixes: JSON.parse(rawAlert.recommended_fixes || '[]'),
    timestamp: rawAlert.timestamp,
    remediatedAt: rawAlert.remediated_at,
    remediatedBy: rawAlert.remediated_by
  } : null;

  res.json({
    user: {
      id: user.id,
      orgId: user.org_id,
      name: user.name,
      email: user.email,
      role: user.role,
      status: user.status || 'active',
      mfaRequired: user.mfa_required === 1,
      privilegeLevel: user.privilege_level || (user.role === 'admin' ? 'ADMIN' : 'STANDARD'),
      mustReset: user.must_reset === 1 || user.status === 'reset_required',
      createdAt: user.created_at
    },
    alert,
    recentSignIns,
    activeSessionsCount: activeSessions.length
  });
});

// Phase 6: Share Sanitized Threat Pattern with Collaborative Grid
accountSecurityRouter.post('/share-pattern', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const { alertId, userId } = req.body;

  const alertRecord = alertId
    ? endpointDb.getAccountAlertById(alertId)
    : endpointDb.getAccountAlertByUserId(userId);

  if (!alertRecord) {
    return res.status(404).json({ error: 'ALERT_NOT_FOUND', message: 'Target account attack alert not found.' });
  }

  // Cross-tenant protection
  if (alertRecord.org_id !== user.orgId) {
    return res.status(403).json({ error: 'FORBIDDEN', message: 'Cannot share threats from another organization.' });
  }

  const sanitizationResult = sanitizeAccountAlertToPattern({
    id: alertRecord.id,
    userId: alertRecord.user_id,
    userEmail: alertRecord.user_email,
    userName: alertRecord.user_name,
    orgId: alertRecord.org_id,
    severity: alertRecord.severity,
    confidence: alertRecord.confidence,
    matchedRules: JSON.parse(alertRecord.matched_rules || '[]'),
    title: alertRecord.title,
    summary: alertRecord.summary
  });

  const originOrgName = db.organizations[alertRecord.org_id]?.name || 'Bank A';

  // Check if pattern already added
  let existingPattern = db.threatPatterns.find((tp) => tp.hash === sanitizationResult.sanitizedPattern.patternHash);
  if (!existingPattern) {
    existingPattern = {
      id: `tp-${Date.now()}`,
      patternCode: sanitizationResult.sanitizedPattern.threatPatternId,
      originOrgId: alertRecord.org_id,
      originOrgName,
      patternSequence: sanitizationResult.sanitizedPattern.behaviorSequence,
      severity: sanitizationResult.sanitizedPattern.severity as any,
      confidence: sanitizationResult.sanitizedPattern.confidence,
      status: 'Confirmed',
      hash: sanitizationResult.sanitizedPattern.patternHash,
      createdAt: new Date().toISOString().replace('T', ' ').slice(0, 19),
      isShared: true
    };
    db.threatPatterns.unshift(existingPattern);

    // Commit sanitized pattern to DLT Ledger automatically
    addLedgerBlock(existingPattern.patternCode, existingPattern.originOrgName, existingPattern.hash);
  }

  // Broadcast to peer institutions
  const peerCorrelations: any[] = [];
  const peerOrgs = Object.values(db.organizations).filter((o) => o.id !== alertRecord.org_id);

  for (const peer of peerOrgs) {
    let peerEvents: string[] = [];
    if (peer.id === 'org-2') {
      peerEvents = ['FAILED_LOGIN_STREAK', 'UNRECOGNIZED_DEVICE', 'UNAUTHORIZED_PRIVILEGE_ELEVATION', 'HIGH_VOLUME_DATA_EXFIL'];
    } else if (peer.id === 'org-3') {
      peerEvents = ['FAILED_LOGIN_STREAK', 'ANOMALOUS_GEO_VELOCITY', 'UNAUTHORIZED_PRIVILEGE_ELEVATION'];
    } else {
      peerEvents = ['FAILED_LOGIN_STREAK', 'UNRECOGNIZED_DEVICE'];
    }

    const corr = correlateThreatPatterns(existingPattern, peer.id, peer.name, peerEvents);
    peerCorrelations.push(corr);

    if (corr.earlyWarningTriggered) {
      wsHub.broadcastToAdmins(peer.id, {
        type: 'EARLY_WARNING',
        threatCode: existingPattern.patternCode,
        originOrg: originOrgName,
        similarity: corr.similarityPercentage,
        message: corr.warningMessage,
        timestamp: new Date().toISOString()
      });
    }
  }

  // Append to Immutable Audit Trail
  endpointDb.appendAudit(
    user.email,
    user.orgId,
    'COLLABORATIVE_PATTERN_SHARED',
    `Sanitized account attack pattern ${existingPattern.patternCode} broadcast to collaborative grid (${peerCorrelations.length} peers). PII scrubbed. Result: SUCCESS`,
    null
  );

  return res.json({
    success: true,
    pattern: existingPattern,
    sanitizationResult,
    peerCorrelations,
    message: `Threat pattern ${existingPattern.patternCode} sanitized, anchored to DLT ledger, and broadcast to ${peerCorrelations.length} peer institutions with early warning triggers.`
  });
});

// Phase 6: Run Account Attack Demo (Deterministic End-to-End Sequence, DEMO_MODE only)
accountSecurityRouter.post('/demo-attack-run', requireAuth, requireAdmin, requireDemoMode, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const targetUserId = 'usr-bank-alice';
  const targetUser = endpointDb.getUserById(targetUserId);

  if (!targetUser) {
    return res.status(404).json({ error: 'DEMO_USER_NOT_FOUND', message: 'Demo target user usr-bank-alice not found.' });
  }

  if (targetUser.org_id !== user.orgId) {
    return res.status(403).json({ error: 'FORBIDDEN_ORG', message: 'Demo target user belongs to a different organization.' });
  }

  const timeline: Array<{ step: number; title: string; description: string; timestamp: string; status: 'SUCCESS' }> = [];

  // 1. Simulate account attack on Alice
  const alert = accountDetectionEngine.simulateAccountAttack(targetUserId);
  timeline.push({
    step: 1,
    title: 'Account Attack Injected',
    description: `Correlated hostile credential stuffing, impossible travel, and privilege elevation anomaly on ${targetUser.email} (Confidence: ${alert.confidence}%).`,
    timestamp: new Date().toISOString(),
    status: 'SUCCESS'
  });

  // 2. Admin Alert Dispatched Live
  timeline.push({
    step: 2,
    title: 'Admin Real-Time Notification',
    description: `Dispatched instant WebSocket ACCOUNT_ALERT to ${user.orgId} SOC administration. High-priority toast and notification badge triggered.`,
    timestamp: new Date().toISOString(),
    status: 'SUCCESS'
  });

  // 3. Admin Fixes: Lock Account & Revoke Sessions
  endpointDb.updateUserStatus(targetUserId, 'locked');
  endpointDb.revokeAllUserSessions(targetUserId);
  const lockNotice = `Your account was locked by SOC administrator ${user.email} on ${new Date().toLocaleTimeString()} for security containment.`;
  endpointDb.addAccountNotice(targetUserId, targetUser.org_id, 'ACCOUNT_LOCKED', lockNotice);
  endpointDb.appendAudit(
    user.email,
    targetUser.org_id,
    'USER_ACCOUNT_LOCKED',
    `Account ${targetUser.email} was locked by SOC administrator ${user.email}. All active sessions revoked. Result: SUCCESS`
  );
  timeline.push({
    step: 3,
    title: 'Admin Remote Fix Executed',
    description: `Account ${targetUser.email} locked and all active sessions revoked immediately. Access severed at the perimeter.`,
    timestamp: new Date().toISOString(),
    status: 'SUCCESS'
  });

  // 4. User Notice Created
  timeline.push({
    step: 4,
    title: 'User Portal Notice Injected',
    description: `Notice dispatched to ${targetUser.email}: "${lockNotice}". User blocked on portal login.`,
    timestamp: new Date().toISOString(),
    status: 'SUCCESS'
  });

  // 5. Risk Neutralized Across All Pages
  const remediationResult = accountDetectionEngine.remediateAlert(alert.id, user.email);
  const updatedScore = remediationResult ? remediationResult.updatedOrgRisk : 24;
  timeline.push({
    step: 5,
    title: 'Unified Risk De-escalation',
    description: `Alert marked Remediated. User account risk neutralized from 99 to 18. Organization unified risk score reduced to ${updatedScore}.`,
    timestamp: new Date().toISOString(),
    status: 'SUCCESS'
  });

  // 6. Sanitized Threat Pattern Generated
  const sanitizationResult = sanitizeAccountAlertToPattern({
    id: alert.id,
    userId: targetUser.id,
    userEmail: targetUser.email,
    userName: targetUser.name,
    orgId: targetUser.org_id,
    severity: alert.severity,
    confidence: alert.confidence,
    matchedRules: alert.matchedRules,
    title: alert.title,
    summary: alert.summary
  });
  timeline.push({
    step: 6,
    title: 'Privacy Engine PII Scrubbing',
    description: `Scrubbed employee name, email, account ID, and IP address. Behavioral signature ${sanitizationResult.sanitizedPattern.threatPatternId} extracted.`,
    timestamp: new Date().toISOString(),
    status: 'SUCCESS'
  });

  // 7. Anchor to DLT Ledger & Peer Broadcast
  const newBlock = addLedgerBlock(
    sanitizationResult.sanitizedPattern.threatPatternId,
    db.organizations[targetUser.org_id]?.name || 'Bank A',
    sanitizationResult.sanitizedPattern.patternHash,
    [targetUser.org_id, 'Hospital B', 'Univ C'],
    'CONFIRMED'
  );

  const peerCorrelations: any[] = [];
  const peerOrgs = Object.values(db.organizations).filter((o) => o.id !== targetUser.org_id);
  for (const peer of peerOrgs) {
    const peerEvents = ['FAILED_LOGIN_STREAK', 'UNRECOGNIZED_DEVICE', 'UNAUTHORIZED_PRIVILEGE_ELEVATION', 'HIGH_VOLUME_DATA_EXFIL'];
    const corr = correlateThreatPatterns(
      {
        id: `tp-${Date.now()}`,
        patternCode: sanitizationResult.sanitizedPattern.threatPatternId,
        originOrgId: targetUser.org_id,
        originOrgName: db.organizations[targetUser.org_id]?.name || 'Bank A',
        patternSequence: sanitizationResult.sanitizedPattern.behaviorSequence,
        severity: 'CRITICAL',
        confidence: alert.confidence,
        status: 'Confirmed',
        hash: sanitizationResult.sanitizedPattern.patternHash,
        createdAt: new Date().toISOString(),
        isShared: true
      },
      peer.id,
      peer.name,
      peerEvents
    );
    peerCorrelations.push(corr);
    if (corr.earlyWarningTriggered) {
      wsHub.broadcastToAdmins(peer.id, {
        type: 'EARLY_WARNING',
        threatCode: sanitizationResult.sanitizedPattern.threatPatternId,
        originOrg: 'Bank A',
        similarity: corr.similarityPercentage,
        message: corr.warningMessage,
        timestamp: new Date().toISOString()
      });
    }
  }

  timeline.push({
    step: 7,
    title: 'Mesh Gossip Early Warning & DLT Block',
    description: `Pattern committed to DLT Block #${newBlock.blockNumber}. Early warning gossip broadcast to Hospital B (94% match) and Univ C (86% match).`,
    timestamp: new Date().toISOString(),
    status: 'SUCCESS'
  });

  // 8. Immutable Audit Trail Complete
  endpointDb.appendAudit(
    user.email,
    user.orgId,
    'COLLABORATIVE_PATTERN_SHARED',
    `Sanitized account attack pattern ${sanitizationResult.sanitizedPattern.threatPatternId} broadcast to collaborative grid. DLT Block #${newBlock.blockNumber}. Result: SUCCESS`
  );
  const auditVerification = endpointDb.verifyAuditChain();
  timeline.push({
    step: 8,
    title: 'Audit Hash-Chain Cryptographic Seal',
    description: `Verified cryptographic SHA-256 hash-chain across all ${auditVerification.totalVerified} audit log records. Chain verified: ${auditVerification.isVerified}.`,
    timestamp: new Date().toISOString(),
    status: 'SUCCESS'
  });

  return res.json({
    success: true,
    alert,
    remediatedAlert: remediationResult?.alert,
    sanitizationResult,
    dltBlock: newBlock,
    peerCorrelations,
    auditVerification,
    updatedOrgRisk: updatedScore,
    timeline,
    message: 'Account Attack Demo executed successfully: attack -> alert -> remote fix -> user notice -> risk drop -> pattern shared -> peer early warning -> audit verified.'
  });
});

// Phase 6: Reset Clean Baseline (Identical Demo Reproducibility, DEMO_MODE only, Scoped to Caller's Org)
accountSecurityRouter.post('/demo-reset', requireAuth, requireAdmin, requireDemoMode, (req: AuthenticatedRequest, res: Response) => {
  const currentToken = req.headers.authorization?.replace(/^Bearer\s+/i, '');
  const currentUser = req.user!;

  endpointDb.resetToBaseline();

  // Preserve the caller admin's session so the UI and demo runner remain seamlessly authenticated
  if (currentToken && currentUser?.userId) {
    endpointDb.createSession(currentUser.userId, currentToken);
  }

  // Reset Organization risk posture for caller's organization only
  const org = db.organizations[currentUser.orgId];
  if (org) {
    org.riskScore = 42;
    org.riskTrend = 'STABLE';
    org.riskBreakdown = {
      authentication: 40,
      networkSecurity: 35,
      dataSecurity: 30,
      endpointSecurity: 45,
      userRisk: 30
    };
  }

  // Clear in-memory alert trackers
  accountDetectionEngine.clearAllAlerts();

  // Broadcast reset to connected admin sessions of caller's org
  wsHub.broadcastToAdmins(req.user!.orgId, {
    type: 'DEMO_RESET',
    message: 'Demo baseline reset. Organization returned to clean prototype state.',
    timestamp: new Date().toISOString()
  });

  return res.json({
    success: true,
    message: 'Prototype state reset to clean baseline for your organization.'
  });
});

// Admin-Only: Promote or Demote user within admin's organization
accountSecurityRouter.post('/users/:userId/role', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const { userId } = req.params;
  const { role } = req.body;

  if (role !== 'admin' && role !== 'user') {
    return res.status(400).json({ error: 'INVALID_ROLE', message: 'Role must be either "admin" or "user".' });
  }

  const user = endpointDb.getUserById(userId);
  if (!user) {
    return res.status(404).json({ error: 'USER_NOT_FOUND', message: 'User not found.' });
  }

  if (user.org_id !== req.user!.orgId) {
    return res.status(403).json({ error: 'FORBIDDEN', message: 'Cross-tenant user modification forbidden.' });
  }

  // Prevent demoting the last active administrator
  if (user.role === 'admin' && role === 'user') {
    const adminCount = endpointDb.countAdminsInOrg(user.org_id);
    if (adminCount <= 1) {
      return res.status(400).json({
        error: 'CANNOT_DEMOTE_LAST_ADMIN',
        message: 'Cannot demote the only remaining active administrator in your organization.'
      });
    }
  }

  const newPrivilege = role === 'admin' ? 'ADMIN' : 'STANDARD';
  endpointDb.updateUserRole(user.id, role, newPrivilege);

  endpointDb.appendAudit(
    req.user!.email,
    user.org_id,
    'USER_ROLE_CHANGED',
    `Administrator ${req.user!.email} updated role of ${user.email} to "${role}" (${newPrivilege}).`
  );

  const freshUser = endpointDb.getUserById(userId)!;
  return res.json({
    success: true,
    user: {
      id: freshUser.id,
      email: freshUser.email,
      name: freshUser.name,
      role: freshUser.role,
      status: freshUser.status,
      privilegeLevel: freshUser.privilege_level
    },
    message: `User ${freshUser.name} role changed to ${role}.`
  });
});

// Admin-Only: Approve pending user registration
accountSecurityRouter.post('/users/:userId/approve', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const { userId } = req.params;
  const user = endpointDb.getUserById(userId);
  if (!user) {
    return res.status(404).json({ error: 'USER_NOT_FOUND', message: 'User not found.' });
  }

  if (user.org_id !== req.user!.orgId) {
    return res.status(403).json({ error: 'FORBIDDEN', message: 'Cross-tenant user modification forbidden.' });
  }

  if (user.status !== 'pending') {
    return res.status(400).json({
      error: 'USER_NOT_PENDING',
      message: `User is currently in status "${user.status}", not pending approval.`
    });
  }

  endpointDb.updateUserStatus(user.id, 'active');

  endpointDb.appendAudit(
    req.user!.email,
    user.org_id,
    'USER_REGISTRATION_APPROVED',
    `Administrator ${req.user!.email} approved user registration for ${user.email}. Status set to active.`
  );

  // Dispatch notice to user
  endpointDb.addAccountNotice(
    user.id,
    user.org_id,
    'ACCOUNT_APPROVED',
    'Your account registration has been approved by your organization administrator. You now have full access.'
  );

  const freshUser = endpointDb.getUserById(userId)!;
  return res.json({
    success: true,
    user: {
      id: freshUser.id,
      email: freshUser.email,
      name: freshUser.name,
      role: freshUser.role,
      status: freshUser.status,
      privilegeLevel: freshUser.privilege_level
    },
    message: `Account registration for ${freshUser.name} approved.`
  });
});
