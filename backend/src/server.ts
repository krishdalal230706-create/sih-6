import dotenv from 'dotenv';
dotenv.config();

import express, { Request, Response } from 'express';
import http from 'http';
import cors from 'cors';
import helmet from 'helmet';
import crypto from 'crypto';
import { AUTH_CONFIG } from './config/authConfig.js';
import { db } from './models/db.js';
import { endpointDb } from './db/endpointDb.js';
import { wsHub } from './ws/wsHub.js';
import { endpointDetectionEngine } from './engine/endpointDetectionEngine.js';
import { authRouter } from './routes/auth.js';
import { accountSecurityRouter } from './routes/accountSecurity.js';
import { deviceRouter } from './routes/devices.js';
import { commandRouter } from './routes/commands.js';
import { auditRouter } from './routes/audit.js';
import { calculateOrganizationRisk } from './engine/riskEngine.js';
import { correlateThreatPatterns } from './engine/correlationEngine.js';
import { sanitizeIncidentToPattern, sanitizeEndpointEventsToPattern, sanitizeAccountAlertToPattern } from './engine/privacyEngine.js';
import { requireAuth, requireAdmin, requireDemoMode, AuthenticatedRequest } from './middleware/authMiddleware.js';
import {
  verifyLedgerRecordIntegrity,
  verifyLedgerChain,
  addLedgerBlock,
  advanceBlockValidation,
  tamperLedgerRecord,
  restoreLedgerBaseline
} from './engine/dltLedger.js';
import { TelemetryEvent, ThreatPattern } from './types.js';
import { vulnerabilityRouter } from './routes/vulnerabilities.js';
import { syncService } from './services/syncService.js';
import { vulnerabilityDb } from './db/vulnerabilityDb.js';
import { optimizeCyberInvestment } from './engine/investmentOptimizer.js';
import { generalApiLimiter, strictMutationLimiter } from './middleware/rateLimiter.js';
import { validateRequestBody } from './middleware/validator.js';

const app = express();
const PORT = process.env.PORT || 5000;

// CORS configuration with ALLOWED_ORIGIN restriction
const allowedOriginEnv = process.env.ALLOWED_ORIGIN;
const defaultAllowed = ['http://localhost:5173', 'http://127.0.0.1:5173', 'http://localhost:3000', 'http://localhost:5000'];
const configuredOrigins = allowedOriginEnv ? allowedOriginEnv.split(',').map((o) => o.trim()) : defaultAllowed;

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (e.g., mobile apps, curl, server-to-server health checks)
      if (!origin) return callback(null, true);
      if (configuredOrigins.includes('*') || configuredOrigins.includes(origin)) {
        return callback(null, true);
      }
      // Allow localhost and private local network (LAN) in non-production / demo
      if (process.env.NODE_ENV !== 'production' && (
        origin.includes('localhost') ||
        origin.includes('127.0.0.1') ||
        origin.includes('192.168.') ||
        origin.includes('10.') ||
        origin.includes('172.')
      )) {
        return callback(null, true);
      }
      return callback(new Error(`CORS error: Origin ${origin} not permitted.`));
    },
    credentials: true
  })
);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json());

// Security: In-memory sliding window rate limiting for all API routes
app.use('/api', generalApiLimiter);

// Authentication & Identity Routes
app.use('/api/auth', authRouter);

// Account Security & Attack Detection Routes (Module 8 Phase 2)
app.use('/api/account-security', accountSecurityRouter);

// Endpoint Devices & Remote Remediation Routes (Gated behind ENABLE_ENDPOINT_AGENT)
if (AUTH_CONFIG.ENABLE_ENDPOINT_AGENT) {
  app.use('/api/devices', deviceRouter);
  app.use('/api/commands', commandRouter);
} else {
  const disabledHandler = (req: Request, res: Response) => {
    res.status(404).json({ error: 'MODULE_DISABLED', message: 'Endpoint Agent module is disabled in this deployment.' });
  };
  app.use('/api/devices', disabledHandler);
  app.use('/api/commands', disabledHandler);
}

// Cryptographic Audit Trail & Hash Chain Routes
app.use('/api/audit', auditRouter);

// Logger middleware
app.use((req, res, next) => {
  console.log(`[API] ${req.method} ${req.path}`);
  next();
});

// Health check (Public)
app.get('/api/health', (req: Request, res: Response) => {
  res.json({ status: 'Operational', name: 'CyberGuard Grid API', version: '2.0.0-live-intel' });
});

// Vulnerability Intelligence API Routes (Admin SOC only)
app.use('/api/vulnerabilities', requireAuth, requireAdmin, vulnerabilityRouter);

// Sources & Synchronization Endpoints (Admin SOC only)
app.get('/api/sources', requireAuth, requireAdmin, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const sources = await vulnerabilityDb.getSources();
    res.json({ sources });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to retrieve sources' });
  }
});

app.get('/api/sync/status', requireAuth, requireAdmin, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const status = await syncService.getStatus();
    res.json(status);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to retrieve sync status' });
  }
});

app.post('/api/sync/run', requireAuth, requireAdmin, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const status = await syncService.runSync({ force: req.body?.force });
    res.json(status);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to execute synchronization', details: err.message });
  }
});

// 1. Dashboard API (Admin SOC only, scoped strictly to caller's org)
app.get('/api/dashboard', requireAuth, requireAdmin, async (req: AuthenticatedRequest, res: Response) => {
  const org = db.organizations[req.user!.orgId] || Object.values(db.organizations)[0];
  const activeIncidents = db.incidents.filter((i) => i.orgId === org.id && i.status !== 'Resolved');
  const riskResult = calculateOrganizationRisk(org, activeIncidents.length);
  const vulnStats = await vulnerabilityDb.getVulnerabilityStats();

  const topPriority = {
    title: 'Credential Compromise & Lateral Exfiltration Risk',
    riskScore: org.riskBreakdown.authentication,
    affectedAsset: 'Identity Provider & Core Customer Database',
    recommendations: [
      'Force immediate re-authentication & session termination',
      'Enforce FIDO2 / WebAuthn hardware key authentication',
      'Review privileged account escalations',
      'Isolate unrecognized device fingerprints (DEV-UNKNOWN-889)'
    ]
  };

  const threatIntelStats = {
    organizationsConnected: Object.keys(db.organizations).length,
    activeSharedThreats: db.threatPatterns.length * 13 + 1,
    confirmedPatterns: db.threatPatterns.length,
    dltBlocksVerified: db.ledgerRecords.length,
    totalVulnerabilities: vulnStats.total,
    criticalVulnerabilities: vulnStats.critical,
    exploitedVulnerabilities: vulnStats.knownExploited,
    avgCvssScore: vulnStats.avgCvssScore,
    avgCyberGuardScore: vulnStats.avgCyberGuardScore,
    lastSyncTime: vulnStats.lastSyncTime,
    lastSuccessfulSyncTime: vulnStats.lastSuccessfulSyncTime,
    isLive: vulnStats.syncState === 'LIVE'
  };

  const recentActivity = [
    { time: '09:44', text: 'Suspicious exfiltration telemetry detected (+18 Risk)', type: 'ALERT' },
    { time: '09:42', text: 'Multiple failed logins followed by privilege escalation', type: 'THREAT' },
    { time: '09:38', text: 'Cross-organization threat pattern TH-7821 matched (92% similarity)', type: 'CORRELATION' },
    { time: '09:31', text: 'Dynamic risk calculation updated: 78 → 91 CRITICAL', type: 'RISK' },
    { time: '09:20', text: 'Cryptographic proof committed to DLT Ledger (Block #10421)', type: 'LEDGER' },
    { time: '09:05', text: `Phishing attack simulation completed for ${org.name}`, type: 'SIMULATION' }
  ];

  res.json({
    organization: org,
    risk: riskResult,
    topPriority,
    threatIntelStats,
    vulnerabilityStats: vulnStats,
    recentActivity
  });
});

// 2. Organizations API (Admin SOC only, returns caller's own org only)
app.get('/api/organizations/join-code', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const orgId = req.user!.orgId;
  const orgRecord = endpointDb.getOrgById(orgId);
  if (!orgRecord) {
    return res.status(404).json({ error: 'ORGANIZATION_NOT_FOUND', message: 'Organization profile not found.' });
  }

  res.json({
    orgId: orgRecord.id,
    joinCode: orgRecord.join_code,
    requiresApproval: orgRecord.requires_approval === 1,
    optedInCollaborative: orgRecord.opted_in_collaborative === 1
  });
});

app.post('/api/organizations/join-code/regenerate', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const orgId = req.user!.orgId;
  const orgRecord = endpointDb.getOrgById(orgId);
  if (!orgRecord) {
    return res.status(404).json({ error: 'ORGANIZATION_NOT_FOUND', message: 'Organization profile not found.' });
  }

  const prefix = orgRecord.name.replace(/[^A-Za-z]/g, '').slice(0, 4).toUpperCase().padEnd(4, 'X');
  const suffix = crypto.randomBytes(2).toString('hex').toUpperCase();
  const newCode = `${prefix}-${suffix}`;

  endpointDb.updateOrgJoinCode(orgId, newCode);
  endpointDb.appendAudit(
    req.user!.email,
    orgId,
    'JOIN_CODE_REGENERATED',
    `Administrator ${req.user!.email} regenerated organization join code to ${newCode}. Previous code invalidated.`
  );

  res.json({
    success: true,
    joinCode: newCode,
    message: 'Join code successfully regenerated.'
  });
});

app.patch('/api/organizations/settings', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const orgId = req.user!.orgId;
  const { requiresApproval, optedInCollaborative } = req.body;

  endpointDb.updateOrgSettings(orgId, {
    requiresApproval: typeof requiresApproval === 'boolean' ? requiresApproval : undefined,
    optedInCollaborative: typeof optedInCollaborative === 'boolean' ? optedInCollaborative : undefined
  });

  endpointDb.appendAudit(
    req.user!.email,
    orgId,
    'ORG_SETTINGS_UPDATED',
    `Organization settings updated: requiresApproval=${requiresApproval}, optedInCollaborative=${optedInCollaborative}`
  );

  const updated = endpointDb.getOrgById(orgId);
  res.json({
    success: true,
    requiresApproval: updated?.requires_approval === 1,
    optedInCollaborative: updated?.opted_in_collaborative === 1,
    message: 'Organization security settings updated successfully.'
  });
});

app.get('/api/organizations', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const org = db.organizations[req.user!.orgId];
  if (!org) return res.status(404).json({ error: 'ORGANIZATION_NOT_FOUND', message: 'Organization not found' });
  const incidents = db.incidents.filter((i) => i.orgId === org.id && i.status !== 'Resolved');
  const calculatedRisk = calculateOrganizationRisk(org, incidents.length).overallRiskScore;

  res.json({
    organizations: [{ ...org, calculatedRisk }],
    activeOrgId: org.id
  });
});

app.get('/api/organizations/:id', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  if (req.params.id !== req.user!.orgId) {
    endpointDb.appendAudit(req.user!.email, req.user!.orgId, 'CROSS_ORG_ACCESS_BLOCKED', `Blocked attempt to access organization profile for ${req.params.id}`);
    return res.status(403).json({ error: 'FORBIDDEN_ORG', message: 'Access denied: You cannot view profile of another organization.' });
  }

  const org = db.organizations[req.params.id];
  if (!org) return res.status(404).json({ error: 'Organization not found' });
  const incidents = db.incidents.filter((i) => i.orgId === org.id && i.status !== 'Resolved');
  const calculatedRisk = calculateOrganizationRisk(org, incidents.length);
  res.json({ organization: org, calculatedRisk });
});

app.put('/api/organizations/:id', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  if (req.params.id !== req.user!.orgId) {
    endpointDb.appendAudit(req.user!.email, req.user!.orgId, 'CROSS_ORG_ACCESS_BLOCKED', `Blocked attempt to update organization profile for ${req.params.id}`);
    return res.status(403).json({ error: 'FORBIDDEN_ORG', message: 'Access denied: You cannot modify profile of another organization.' });
  }

  const org = db.organizations[req.params.id];
  if (!org) return res.status(404).json({ error: 'Organization not found' });

  const { usersCount, criticalSystems, internetFacingServices, knownVulnerabilities, dataSensitivity, securityControls } = req.body;

  if (usersCount !== undefined) org.usersCount = Number(usersCount);
  if (criticalSystems !== undefined) org.criticalSystems = Number(criticalSystems);
  if (internetFacingServices !== undefined) org.internetFacingServices = Number(internetFacingServices);
  if (knownVulnerabilities !== undefined) org.knownVulnerabilities = Number(knownVulnerabilities);
  if (dataSensitivity !== undefined) org.dataSensitivity = dataSensitivity;
  if (securityControls !== undefined) org.securityControls = securityControls;

  org.lastUpdated = new Date().toISOString();

  // Recalculate risk score
  const incidents = db.incidents.filter((i) => i.orgId === org.id && i.status !== 'Resolved');
  const newRisk = calculateOrganizationRisk(org, incidents.length);
  org.riskScore = newRisk.overallRiskScore;

  res.json({ organization: org, updatedRisk: newRisk });
});

// 3. Cyber Risk API (Admin SOC only, scoped strictly to caller's org)
app.get('/api/risk', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const org = db.organizations[req.user!.orgId];
  if (!org) return res.status(404).json({ error: 'ORGANIZATION_NOT_FOUND', message: 'Organization not found' });
  const incidents = db.incidents.filter((i) => i.orgId === org.id && i.status !== 'Resolved');
  const riskResult = calculateOrganizationRisk(org, incidents.length);
  res.json({ organization: org, riskResult });
});

app.get('/api/risk/:organizationId', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  if (req.params.organizationId !== req.user!.orgId) {
    endpointDb.appendAudit(req.user!.email, req.user!.orgId, 'CROSS_ORG_ACCESS_BLOCKED', `Blocked attempt to view cyber risk for ${req.params.organizationId}`);
    return res.status(403).json({ error: 'FORBIDDEN_ORG', message: 'Access denied: You cannot view cyber risk of another organization.' });
  }

  const org = db.organizations[req.params.organizationId];
  if (!org) return res.status(404).json({ error: 'Organization not found' });
  const incidents = db.incidents.filter((i) => i.orgId === org.id && i.status !== 'Resolved');
  const riskResult = calculateOrganizationRisk(org, incidents.length);
  res.json({ organization: org, riskResult });
});

app.post('/api/risk/recalculate', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const org = db.organizations[req.user!.orgId];
  if (!org) return res.status(404).json({ error: 'Organization not found' });
  const incidents = db.incidents.filter((i) => i.orgId === org.id && i.status !== 'Resolved');
  const newRisk = calculateOrganizationRisk(org, incidents.length);
  org.riskScore = newRisk.overallRiskScore;
  res.json({ success: true, updatedRisk: newRisk });
});

// Direct Remediation Endpoint for Green Button in Attack Simulator & Attack Path
app.post('/api/risk/remediate-weak-point', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const org = db.organizations[req.user!.orgId];
  if (!org) return res.status(404).json({ error: 'Organization not found' });
  const oldScore = org.riskScore;
  const reduction = 24;
  org.riskScore = Math.max(20, org.riskScore - reduction);
  org.riskTrend = 'FALLING';
  org.riskBreakdown.authentication = Math.max(30, org.riskBreakdown.authentication - reduction);

  // Complete first pending response action
  const pendingAction = db.responseActions.find((a) => a.orgId === org.id && a.status !== 'Completed');
  if (pendingAction) {
    pendingAction.status = 'Completed';
  }

  // Resolve main active incident if all actions complete
  const inc = db.incidents.find((i) => i.orgId === org.id && i.status !== 'Resolved');
  if (inc) {
    inc.status = 'Contained';
    inc.timeline.push({
      id: `t-${Date.now()}`,
      time: new Date().toTimeString().slice(0, 8),
      title: 'Critical Weakness Remediated',
      description: 'Enforced FIDO2 WebAuthn hardware key authentication across identity providers.',
      type: 'RESPONSE'
    });
  }

  res.json({
    success: true,
    previousScore: oldScore,
    newScore: org.riskScore,
    reduction,
    remediatedControl: 'Enforced FIDO2 WebAuthn Hardware Keys & Hardware MFA'
  });
});

// 4. Attack Simulator API (Admin SOC only, scoped to caller's org)
app.get('/api/attack-scenarios', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  res.json({ scenarios: db.attackScenarios });
});

app.post('/api/attack-scenarios/:id/simulate', requireAuth, requireAdmin, requireDemoMode, (req: AuthenticatedRequest, res: Response) => {
  const scenario = db.attackScenarios.find((s) => s.id === req.params.id) || db.attackScenarios[0];
  const org = db.organizations[req.user!.orgId] || db.getActiveOrganization();

  // Attack simulation impact on risk
  const simulatedRiskIncrease = Math.min(95, org.riskScore + 5);

  res.json({
    scenario,
    simulationResult: {
      status: 'COMPLETED',
      nodesExecuted: scenario.nodes.length,
      attackPathExecuted: scenario.nodes.map((n) => n.name),
      criticalWeakPoint: scenario.criticalWeakPoint,
      simulatedRiskIncrease,
      recommendedMitigation: scenario.nodes[1]?.recommendedControl || 'Enforce hardware-backed MFA'
    }
  });
});

// 5. Threat Detection & Telemetry Stream API (Admin SOC only, scoped to caller's org)
app.get('/api/telemetry', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  res.json({ telemetryStream: db.telemetryStream });
});

app.post('/api/telemetry/simulate', requireAuth, requireAdmin, requireDemoMode, (req: AuthenticatedRequest, res: Response) => {
  const { eventType, details } = req.body;
  const org = db.organizations[req.user!.orgId] || db.getActiveOrganization();
  const newEvent: TelemetryEvent = {
    id: `tel-${Date.now()}`,
    timestamp: new Date().toTimeString().slice(0, 8),
    eventType: eventType || 'PRIVILEGE_ESCALATION',
    sourceIp: '198.51.100.42',
    user: req.user!.email,
    deviceId: 'DEV-UNKNOWN-889',
    severity: 'CRITICAL',
    details: details || 'Simulated privilege escalation event injected from command center.'
  };

  db.telemetryStream.unshift(newEvent);

  const targetDeviceId = req.body.deviceId || 'DEV-BANK-01';
  const oldRisk = org.riskScore;

  // Process through sliding-window endpoint detection engine
  const detection = endpointDetectionEngine.processEvent(targetDeviceId, org.id, {
    event_type: newEvent.eventType,
    details: newEvent.details,
    severity: newEvent.severity,
    timestamp: new Date().toISOString()
  });

  res.json({
    event: newEvent,
    threatDetected: detection ? {
      title: detection.title,
      confidence: detection.confidence,
      severity: detection.severity,
      reason: detection.summary,
      matchedRules: detection.matchedRules,
      factorContributions: detection.factorContributions
    } : {
      title: 'POSSIBLE ACCOUNT COMPROMISE & ELEVATED PRIVILEGE',
      confidence: 94,
      severity: 'CRITICAL',
      reason: 'Multiple authentication anomalies followed by privileged access and unauthorized role change.'
    },
    riskTransition: {
      previousScore: oldRisk,
      newScore: org.riskScore,
      delta: org.riskScore - oldRisk
    }
  });
});

// 6. Incident Management API (Admin SOC only, scoped strictly to caller's org)
app.get('/api/incidents', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const list = db.incidents.filter((i) => i.orgId === req.user!.orgId);
  res.json({ incidents: list });
});

app.get('/api/incidents/:id', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const inc = db.incidents.find((i) => i.id === req.params.id || i.incidentId === req.params.id);
  if (!inc) return res.status(404).json({ error: 'Incident not found' });
  if (inc.orgId !== req.user!.orgId) {
    endpointDb.appendAudit(req.user!.email, req.user!.orgId, 'CROSS_ORG_ACCESS_BLOCKED', `Unauthorized attempt to access incident ${req.params.id}`);
    return res.status(403).json({ error: 'FORBIDDEN_ORG', message: 'Access denied: Incident belongs to another organization.' });
  }

  const actions = db.responseActions.filter((a) => a.incidentId === inc.id && a.orgId === req.user!.orgId);
  res.json({ incident: inc, responseActions: actions });
});

app.post('/api/incidents/:id/respond', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const { actionId, markStatus } = req.body;
  const inc = db.incidents.find((i) => i.id === req.params.id || i.incidentId === req.params.id);
  if (!inc) return res.status(404).json({ error: 'Incident not found' });
  if (inc.orgId !== req.user!.orgId) {
    endpointDb.appendAudit(req.user!.email, req.user!.orgId, 'CROSS_ORG_ACCESS_BLOCKED', `Unauthorized attempt to respond to incident ${req.params.id}`);
    return res.status(403).json({ error: 'FORBIDDEN_ORG', message: 'Access denied: Incident belongs to another organization.' });
  }

  const action = db.responseActions.find((a) => a.id === actionId && a.orgId === req.user!.orgId) || db.responseActions.find((a) => a.orgId === req.user!.orgId);
  if (!action) return res.status(404).json({ error: 'Response action not found' });

  action.status = markStatus || 'Completed';

  // Lower organization risk score appropriately
  const org = db.organizations[action.orgId];
  const oldScore = org ? org.riskScore : 42;
  const reduction = action.estimatedRiskReduction;
  if (org && action.status === 'Completed') {
    org.riskScore = Math.max(20, org.riskScore - reduction);
    org.riskBreakdown.authentication = Math.max(30, org.riskBreakdown.authentication - reduction);
  }

  // If all actions completed, resolve incident
  const remainingPending = db.responseActions.filter((a) => a.incidentId === action.incidentId && a.status !== 'Completed');
  if (remainingPending.length === 0 && inc) {
    inc.status = 'Resolved';
    inc.timeline.push({
      id: `t-${Date.now()}`,
      time: new Date().toTimeString().slice(0, 8),
      title: 'Incident Resolved & Contained',
      description: 'All automated remediation actions successfully executed. System risk posture normalized.',
      type: 'RESOLUTION'
    });
  }

  res.json({
    success: true,
    action,
    riskReduction: {
      previousScore: oldScore,
      newScore: org ? org.riskScore : oldScore,
      pointsReduced: reduction
    }
  });
});

// 7. Response Center API (Admin SOC only, scoped strictly to caller's org)
app.get('/api/response-actions', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const actions = db.responseActions.filter((a) => a.orgId === req.user!.orgId);
  res.json({ responseActions: actions });
});

// 8. Privacy Engine API (Admin SOC only, scoped to caller's org)
app.post('/api/privacy/sanitize', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const { incidentId } = req.body;
  const inc = db.incidents.find((i) => i.id === incidentId || i.incidentId === incidentId) || db.incidents.find((i) => i.orgId === req.user!.orgId);
  if (!inc) return res.status(404).json({ error: 'Incident not found' });
  if (inc.orgId !== req.user!.orgId) {
    endpointDb.appendAudit(req.user!.email, req.user!.orgId, 'CROSS_ORG_ACCESS_BLOCKED', `Unauthorized attempt to sanitize incident belonging to ${inc.orgId}`);
    return res.status(403).json({ error: 'FORBIDDEN_ORG', message: 'Access denied: Cannot sanitize another organization incident.' });
  }

  const result = sanitizeIncidentToPattern(inc);

  // Check if pattern already added
  let existingPattern = db.threatPatterns.find((tp) => tp.hash === result.sanitizedPattern.patternHash);
  if (!existingPattern) {
    existingPattern = {
      id: `tp-${Date.now()}`,
      patternCode: result.sanitizedPattern.threatPatternId,
      originOrgId: inc.orgId,
      originOrgName: db.organizations[inc.orgId]?.name || 'Bank A',
      patternSequence: result.sanitizedPattern.behaviorSequence,
      severity: inc.severity,
      confidence: inc.confidence,
      status: 'Confirmed',
      hash: result.sanitizedPattern.patternHash,
      createdAt: new Date().toISOString().replace('T', ' ').slice(0, 19),
      isShared: true
    };
    db.threatPatterns.unshift(existingPattern);

    // Commit to DLT Ledger automatically
    addLedgerBlock(existingPattern.patternCode, existingPattern.originOrgName, existingPattern.hash);
  }

  res.json({
    sanitizationResult: result,
    createdPattern: existingPattern
  });
});

app.post('/api/privacy/share-endpoint-pattern', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const { deviceId, incidentId, alertId, userId } = req.body;

  let result;
  let originOrgId = user.orgId;
  let originOrgName = db.organizations[originOrgId]?.name || 'Bank A';

  if (alertId || userId) {
    const alertRecord = alertId
      ? endpointDb.getAccountAlertById(alertId)
      : endpointDb.getAccountAlertByUserId(userId);

    if (!alertRecord) {
      return res.status(404).json({ error: 'ALERT_NOT_FOUND', message: 'Target account alert not found' });
    }
    if (alertRecord.org_id !== user.orgId) {
      endpointDb.appendAudit(user.email, user.orgId, 'CROSS_ORG_ACCESS_BLOCKED', `Unauthorized attempt to share alert from org ${alertRecord.org_id}`);
      return res.status(403).json({ error: 'FORBIDDEN_ORG', message: 'Account alert belongs to another organization.' });
    }

    result = sanitizeAccountAlertToPattern({
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
  } else if (deviceId) {
    const device = endpointDb.getDeviceById(deviceId);
    if (!device) {
      return res.status(404).json({ error: 'DEVICE_NOT_FOUND', message: 'Target device not found' });
    }
    if (device.org_id !== user.orgId) {
      endpointDb.appendAudit(user.email, user.orgId, 'CROSS_ORG_ACCESS_BLOCKED', `Unauthorized attempt to share device pattern from org ${device.org_id}`);
      return res.status(403).json({ error: 'FORBIDDEN_ORG', message: 'Target device belongs to another organization.' });
    }

    const events = endpointDb.getRecentDeviceEvents(deviceId, 30);
    result = sanitizeEndpointEventsToPattern(device.id, device.hostname, device.user_email || user.email, events, user.orgId);
  } else {
    const inc = db.incidents.find((i) => i.id === incidentId || i.incidentId === incidentId) || db.incidents.find((i) => i.orgId === user.orgId);
    if (!inc || inc.orgId !== user.orgId) {
      return res.status(403).json({ error: 'FORBIDDEN_ORG', message: 'Incident belongs to another organization.' });
    }
    result = sanitizeIncidentToPattern(inc);
    originOrgId = inc.orgId;
    originOrgName = db.organizations[originOrgId]?.name || originOrgName;
  }

  // Check if pattern already added
  let existingPattern = db.threatPatterns.find((tp) => tp.hash === result.sanitizedPattern.patternHash);
  if (!existingPattern) {
    existingPattern = {
      id: `tp-${Date.now()}`,
      patternCode: result.sanitizedPattern.threatPatternId,
      originOrgId,
      originOrgName,
      patternSequence: result.sanitizedPattern.behaviorSequence,
      severity: result.sanitizedPattern.severity as any,
      confidence: result.sanitizedPattern.confidence,
      status: 'Confirmed',
      hash: result.sanitizedPattern.patternHash,
      createdAt: new Date().toISOString().replace('T', ' ').slice(0, 19),
      isShared: true
    };
    db.threatPatterns.unshift(existingPattern);

    // Commit sanitized pattern to DLT Ledger automatically
    addLedgerBlock(existingPattern.patternCode, existingPattern.originOrgName, existingPattern.hash);
  }

  // Cross-institutional correlation across peer organizations
  const peerCorrelations: any[] = [];
  const peerOrgs = Object.values(db.organizations).filter((o) => o.id !== originOrgId);

  for (const peer of peerOrgs) {
    let peerEvents: string[] = [];
    if (peer.id === 'org-2') {
      peerEvents = ['FAILED_LOGIN', 'NEW_DEVICE', 'UNUSUAL_LOCATION', 'PRIVILEGE_ESCALATION', 'LARGE_DATA_TRANSFER'];
    } else if (peer.id === 'org-4') {
      peerEvents = ['FAILED_LOGIN', 'NEW_DEVICE', 'PRIVILEGE_ESCALATION', 'LARGE_DATA_TRANSFER'];
    } else {
      peerEvents = ['FAILED_LOGIN', 'UNUSUAL_LOCATION', 'DATA_ACCESS'];
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

  // Append to Audit Trail
  endpointDb.appendAudit(
    user.email,
    user.orgId,
    'COLLABORATIVE_PATTERN_SHARED',
    `Shared sanitized threat pattern ${existingPattern.patternCode} derived from ${deviceId || incidentId} incident. Masked ${result.maskedFields.length} sensitive fields. Broadcast to ${peerCorrelations.length} peer institutions.`,
    deviceId || null
  );

  return res.json({
    success: true,
    pattern: existingPattern,
    sanitizationResult: result,
    peerCorrelations,
    message: `Threat pattern ${existingPattern.patternCode} sanitized, anchored to DLT ledger, and broadcast to ${peerCorrelations.length} collaborative peer institutions.`
  });
});

// 9. Threat Intelligence Library API (Admin SOC only, returns sanitized patterns)
app.get('/api/threat-intelligence', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  res.json({ threatPatterns: db.threatPatterns });
});

app.post('/api/threat-intelligence/compare', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const { threatCode, targetOrgId } = req.body;
  const pattern = db.threatPatterns.find((tp) => tp.patternCode === threatCode) || db.threatPatterns[0];
  const targetOrg = db.organizations[targetOrgId || 'org-2'] || db.organizations['org-2'];

  let targetEvents: string[] = [];
  if (targetOrg.id === 'org-2') {
    targetEvents = ['FAILED_LOGIN', 'NEW_DEVICE', 'UNUSUAL_LOCATION', 'PRIVILEGE_ESCALATION', 'LARGE_DATA_TRANSFER'];
  } else if (targetOrg.id === 'org-4') {
    targetEvents = ['FAILED_LOGIN', 'NEW_DEVICE', 'PRIVILEGE_ESCALATION', 'LARGE_DATA_TRANSFER'];
  } else if (targetOrg.id === 'org-3') {
    targetEvents = ['FAILED_LOGIN', 'UNUSUAL_LOCATION', 'DATA_ACCESS'];
  } else {
    targetEvents = ['FAILED_LOGIN', 'CLEARED_LOGS'];
  }

  const correlation = correlateThreatPatterns(pattern, targetOrg.id, targetOrg.name, targetEvents);

  res.json({ correlation });
});

// 10. Collaborative Network API (Admin SOC only, sanitized peer node intelligence only)
app.get('/api/network', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const callerOrgId = req.user!.orgId;
  const nodes = Object.values(db.organizations).map((o) => ({
    id: o.id,
    name: o.name,
    type: o.type,
    riskScore: o.id === callerOrgId ? o.riskScore : undefined, // Never leak exact raw risk score of peer organizations
    riskBand: o.riskScore >= 80 ? 'CRITICAL' : o.riskScore >= 65 ? 'HIGH' : o.riskScore >= 45 ? 'MEDIUM' : 'LOW',
    isCallerOrg: o.id === callerOrgId,
    sharedCount: db.threatPatterns.filter((p) => p.originOrgId === o.id).length
  }));

  const links = [
    { source: 'org-1', target: 'org-2', label: 'TH-7821 Pattern Shared (92% Match)' },
    { source: 'org-1', target: 'org-4', label: 'TH-4019 Telemetry Exchange' },
    { source: 'org-4', target: 'org-3', label: 'Academic Cyber Threat Feed' },
    { source: 'org-2', target: 'org-5', label: 'Healthcare Underwriting Intel' }
  ];

  res.json({ nodes, links });
});

app.post('/api/network/broadcast', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const { threatCode } = req.body;
  const pattern = db.threatPatterns.find((tp) => tp.patternCode === threatCode) || db.threatPatterns[0];
  const sourceOrg = db.organizations[req.user!.orgId] || db.getActiveOrganization();

  // Peer organizations in the mesh
  const peerOrgs = Object.values(db.organizations).filter((o) => o.id !== sourceOrg.id);

  // Correlate across each peer organization in the mesh
  const meshPropagation = peerOrgs.map((peer) => {
    let targetEvents: string[] = [];
    if (peer.id === 'org-2') {
      targetEvents = ['FAILED_LOGIN', 'NEW_DEVICE', 'UNUSUAL_LOCATION', 'PRIVILEGE_ESCALATION', 'LARGE_DATA_TRANSFER'];
    } else if (peer.id === 'org-4') {
      targetEvents = ['FAILED_LOGIN', 'NEW_DEVICE', 'PRIVILEGE_ESCALATION', 'LARGE_DATA_TRANSFER'];
    } else if (peer.id === 'org-3') {
      targetEvents = ['FAILED_LOGIN', 'UNUSUAL_LOCATION', 'DATA_ACCESS'];
    } else {
      targetEvents = ['FAILED_LOGIN', 'CLEARED_LOGS'];
    }

    const correlation = correlateThreatPatterns(pattern, peer.id, peer.name, targetEvents);
    const earlyWarningTriggered = correlation.similarityPercentage >= 65;

    return {
      peerOrgId: peer.id,
      peerOrgName: peer.name,
      peerType: peer.type,
      similarityPercentage: correlation.similarityPercentage,
      confidence: correlation.confidence,
      earlyWarningTriggered,
      warningMessage: correlation.warningMessage,
      matchingEvents: correlation.sequenceComparison.matchingEvents,
      missingEvents: correlation.sequenceComparison.missingEvents,
      alignedBreakdown: correlation.sequenceComparison.alignedBreakdown,
      status: earlyWarningTriggered ? 'EARLY_WARNING_TRIGGERED' : 'RECEIVED_CLEARED',
      latencyMs: 20 + (peer.name.length * 3) % 25
    };
  });

  // Ensure pattern is recorded in DLT ledger
  let ledgerBlock = db.ledgerRecords.find((l) => l.threatId === pattern.patternCode);
  if (!ledgerBlock) {
    ledgerBlock = addLedgerBlock(pattern.patternCode, sourceOrg.name, pattern.hash);
  }

  // Also mark pattern as shared
  pattern.isShared = true;

  res.json({
    success: true,
    pattern,
    sourceOrg: { id: sourceOrg.id, name: sourceOrg.name },
    ledgerBlock,
    broadcastTimestamp: new Date().toISOString(),
    consensusValidators: ['Bank A', 'Hospital B', 'University C', 'FinTech Corp'],
    meshPropagation
  });
});

// 11. DLT Trust Ledger API (Admin SOC only)
app.get('/api/ledger', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  res.json({ ledgerRecords: db.ledgerRecords });
});

app.post('/api/ledger/add', requireAuth, requireAdmin, strictMutationLimiter, validateRequestBody({ threatId: { type: 'string', required: true, minLength: 2, maxLength: 50 } }), (req: AuthenticatedRequest, res: Response) => {
  const { threatId, hash, validators, status } = req.body;
  if (!threatId) return res.status(400).json({ error: 'threatId required' });
  const reporterName = db.organizations[req.user!.orgId]?.name || req.user!.orgId;
  const newBlock = addLedgerBlock(
    threatId || 'TH-CUSTOM',
    reporterName,
    hash || `custom-hash-${Date.now()}`,
    validators,
    status
  );
  res.json({ success: true, block: newBlock, ledgerRecords: db.ledgerRecords });
});

app.post('/api/ledger/verify', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const { blockNumber } = req.body;
  const chainVerification = verifyLedgerChain();
  const blockNum = Number(blockNumber) || (db.ledgerRecords[db.ledgerRecords.length - 1]?.blockNumber || 10421);
  const blockVerification = verifyLedgerRecordIntegrity(blockNum);

  res.json({
    verification: blockVerification,
    chainVerification,
    isChainValid: chainVerification.isVerified,
    brokenBlockNumber: chainVerification.brokenBlockNumber,
    details: chainVerification.isVerified
      ? chainVerification.details
      : blockVerification.details
  });
});

app.post('/api/ledger/validate', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const { blockNumber } = req.body;
  const num = Number(blockNumber) || 10421;
  const validator = db.organizations[req.user!.orgId]?.name || 'Bank A';
  const updatedBlock = advanceBlockValidation(num, validator);

  if (!updatedBlock) {
    return res.status(404).json({ error: `Block #${num} not found` });
  }

  res.json({
    success: true,
    block: updatedBlock,
    ledgerRecords: db.ledgerRecords,
    message: `Validator signature from "${validator}" added. Status: ${updatedBlock.status}`
  });
});
app.post('/api/ledger/tamper', requireAuth, requireAdmin, requireDemoMode, strictMutationLimiter, (req: AuthenticatedRequest, res: Response) => {
  const { blockNumber, newThreatId } = req.body;
  const targetNum = Number(blockNumber) || 10420;
  const result = tamperLedgerRecord(targetNum, newThreatId);

  res.json({
    ...result,
    ledgerRecords: db.ledgerRecords
  });
});

app.post('/api/ledger/reset', requireAuth, requireAdmin, requireDemoMode, strictMutationLimiter, (req: AuthenticatedRequest, res: Response) => {
  const baseline = restoreLedgerBaseline();
  res.json({
    success: true,
    ledgerRecords: baseline,
    message: 'DLT Ledger successfully restored to valid baseline state.'
  });
});

// 12. Automated Demo Mode Step Controller & Reset (Admin SOC only, DEMO_MODE only, Scoped to Caller's Org)
app.post('/api/demo/reset', requireAuth, requireAdmin, requireDemoMode, strictMutationLimiter, (req: AuthenticatedRequest, res: Response) => {
  const orgId = req.user!.orgId;
  const org = db.organizations[orgId];
  if (org) {
    org.riskScore = 42;
    org.riskTrend = 'FALLING';
    org.riskBreakdown = {
      authentication: 45,
      networkSecurity: 40,
      dataSecurity: 42,
      endpointSecurity: 38,
      userRisk: 45
    };
  }
  endpointDb.resetToBaseline();
  endpointDetectionEngine.resetBaseline();
  res.json({
    success: true,
    message: `CyberGuard Grid demo state for ${org ? org.name : orgId} successfully reset to clean baseline.`,
    activeOrg: org || db.organizations[orgId],
    organizations: org ? [org] : [],
    ledgerRecords: db.ledgerRecords
  });
});

app.post('/api/demo/step', requireAuth, requireAdmin, requireDemoMode, validateRequestBody({ step: { type: 'number', required: true, min: 1, max: 4 } }), (req: AuthenticatedRequest, res: Response) => {
  const { step } = req.body;
  const currentStep = Number(step) || 1;
  const orgId = req.user!.orgId;
  const org = db.organizations[orgId] || db.getActiveOrganization();

  if (currentStep === 1) {
    org.riskScore = 42;
    org.riskTrend = 'FALLING';
    org.riskBreakdown = {
      authentication: 45,
      networkSecurity: 40,
      dataSecurity: 42,
      endpointSecurity: 38,
      userRisk: 45
    };
    const inc = db.incidents.find((i) => i.orgId === orgId);
    if (inc) inc.status = 'Contained';
  } else if (currentStep === 2) {
    org.riskScore = 78;
    org.riskTrend = 'RISING';
    org.riskBreakdown.authentication = 82;
    org.riskBreakdown.endpointSecurity = 74;
    const inc = db.incidents.find((i) => i.orgId === orgId);
    if (inc) inc.status = 'Detected';
  } else if (currentStep === 3) {
    org.riskScore = 91;
    org.riskTrend = 'RISING';
    org.riskBreakdown.authentication = 95;
    org.riskBreakdown.dataSecurity = 92;
    const inc = db.incidents.find((i) => i.orgId === orgId);
    if (inc) inc.status = 'Investigating';
  } else if (currentStep === 4) {
    org.riskScore = 24;
    org.riskTrend = 'FALLING';
    org.riskBreakdown = {
      authentication: 22,
      networkSecurity: 26,
      dataSecurity: 25,
      endpointSecurity: 20,
      userRisk: 27
    };
    const inc = db.incidents.find((i) => i.orgId === orgId);
    if (inc) inc.status = 'Resolved';
    const action = db.responseActions.find((a) => a.orgId === orgId);
    if (action) action.status = 'Completed';
  }

  res.json({
    step: currentStep,
    activeOrg: org,
    incidents: db.incidents.filter((i) => i.orgId === orgId),
    threatPatterns: db.threatPatterns,
    latestLedgerBlock: db.ledgerRecords[db.ledgerRecords.length - 1]
  });
});

// Module 8 Scripted Endpoint Demo Run & Reset (Gated behind ENABLE_ENDPOINT_AGENT and DEMO_MODE)
app.post('/api/demo/endpoint-run', requireAuth, requireAdmin, requireDemoMode, (req: AuthenticatedRequest, res: Response) => {
  if (!AUTH_CONFIG.ENABLE_ENDPOINT_AGENT) {
    return res.status(404).json({ error: 'MODULE_DISABLED', message: 'Endpoint Agent module is disabled in this deployment.' });
  }

  const deviceId = 'DEV-BANK-01';
  const orgId = req.user!.orgId;

  // 1. Inject multi-stage fake telemetry events
  const fakeEvents = [
    { eventType: 'FAILED_LOGIN', details: 'Rapid brute force logon attempt 1/15 from 198.51.100.42 targeting alice@banka.com' },
    { eventType: 'FAILED_LOGIN', details: 'Rapid brute force logon attempt 15/15: Credential stuffing threshold exceeded' },
    { eventType: 'SUCCESSFUL_LOGIN', details: 'Interactive user logon successful for alice@banka.com' },
    { eventType: 'NEW_DEVICE', details: 'Authentication from previously unseen network adapter GUID' },
    { eventType: 'ANOMALOUS_GEO', details: 'Geographic logon velocity anomaly: Frankfurt, Germany (speed > 800 km/h)' },
    { eventType: 'PRIVILEGE_ESCALATION', details: 'Unauthorized token elevation: SeDebugPrivilege acquired by demo_suspicious' },
    { eventType: 'LARGE_DATA_TRANSFER', details: 'Anomalous outbound encrypted egress volume: 4.8 GB transferred' }
  ];

  for (const fe of fakeEvents) {
    const evt = {
      id: `evt-demo-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      device_id: deviceId,
      event_type: fe.eventType,
      details: fe.details,
      severity: fe.eventType === 'PRIVILEGE_ESCALATION' || fe.eventType === 'LARGE_DATA_TRANSFER' ? 'CRITICAL' : 'HIGH',
      timestamp: new Date().toISOString()
    };
    endpointDb.recordDeviceEvent(evt);
    endpointDetectionEngine.processEvent(deviceId, orgId, evt);
  }

  const detection = endpointDetectionEngine.getLatestDetection(deviceId);

  res.json({
    success: true,
    stage: 'ATTACK_DETECTED',
    deviceId,
    detection,
    message: 'Scripted attack sequence injected on DEV-BANK-01. Sliding window alert emitted to SOC admins.'
  });
});

app.post('/api/demo/endpoint-remediate', requireAuth, requireAdmin, requireDemoMode, (req: AuthenticatedRequest, res: Response) => {
  if (!AUTH_CONFIG.ENABLE_ENDPOINT_AGENT) {
    return res.status(404).json({ error: 'MODULE_DISABLED', message: 'Endpoint Agent module is disabled in this deployment.' });
  }

  const deviceId = 'DEV-BANK-01';
  const orgId = req.user!.orgId;
  const now = new Date().toISOString();

  // 1. Record executed remediation commands in DB
  const killCmd = {
    id: `cmd-demo-kill-${Date.now()}`,
    device_id: deviceId,
    action: 'kill_process',
    params: JSON.stringify({ processName: 'demo_suspicious' }),
    status: 'Executed' as const,
    issued_by: req.user!.email,
    issued_at: now,
    expires_at: new Date(Date.now() + 60000).toISOString(),
    nonce: `n-kill-${Date.now()}`,
    signature: 'sig-verified-demo-kill-001',
    result: 'Harmless tracked process "demo_suspicious" terminated successfully.',
    result_at: now
  };
  endpointDb.recordCommand(killCmd);

  const logoutCmd = {
    id: `cmd-demo-logout-${Date.now()}`,
    device_id: deviceId,
    action: 'force_logout',
    params: JSON.stringify({}),
    status: 'Executed' as const,
    issued_by: req.user!.email,
    issued_at: now,
    expires_at: new Date(Date.now() + 60000).toISOString(),
    nonce: `n-logout-${Date.now()}`,
    signature: 'sig-verified-demo-logout-001',
    result: 'User session tokens invalidated. Workstation session state cleared.',
    result_at: now
  };
  endpointDb.recordCommand(logoutCmd);

  // 2. Transition device status to Remediated and drop device risk
  endpointDb.updateDeviceStatus(deviceId, 'Remediated', 20);

  // 3. Drop Organization Risk via riskEngine
  const org = db.organizations[orgId];
  if (org) {
    org.riskBreakdown.authentication = 25;
    org.riskBreakdown.endpointSecurity = 20;
    org.riskTrend = 'FALLING';
    const newRisk = calculateOrganizationRisk(org, 0);
    org.riskScore = newRisk.overallRiskScore;
  }

  // 4. Sanitize behavioral kill chain and broadcast to collaborative network
  const events = endpointDb.getRecentDeviceEvents(deviceId, 20);
  const sanitized = sanitizeEndpointEventsToPattern(deviceId, 'ALICE-LAPTOP-W11', 'alice@banka.com', events, orgId);

  // Add pattern
  const patternCode = 'TH-8821';
  const existingPattern = {
    id: `tp-endpoint-demo`,
    patternCode,
    originOrgId: orgId,
    originOrgName: org?.name || 'Bank A',
    patternSequence: sanitized.sanitizedPattern.behaviorSequence,
    severity: 'CRITICAL' as const,
    confidence: 96,
    status: 'Confirmed' as const,
    hash: sanitized.sanitizedPattern.patternHash,
    createdAt: now.replace('T', ' ').slice(0, 19),
    isShared: true
  };
  db.threatPatterns.unshift(existingPattern);

  // Anchor to DLT Ledger
  const dltBlock = addLedgerBlock(patternCode, org?.name || 'Bank A', existingPattern.hash, ['Bank A', 'Hospital B', 'University C'], 'CONFIRMED');

  // Trigger peer early warning in Hospital B
  const hospEvents = ['FAILED_LOGIN', 'NEW_DEVICE', 'UNUSUAL_LOCATION', 'PRIVILEGE_ESCALATION', 'LARGE_DATA_TRANSFER'];
  const hospCorr = correlateThreatPatterns(existingPattern, 'org-2', 'Hospital B', hospEvents);

  wsHub.broadcastToAdmins('org-2', {
    type: 'EARLY_WARNING',
    threatCode: patternCode,
    originOrg: org?.name || 'Bank A',
    similarity: hospCorr.similarityPercentage,
    message: hospCorr.warningMessage,
    timestamp: now
  });

  // Notify admins of remediation and score drop
  wsHub.broadcastToAdmins(orgId, {
    type: 'COMMAND_UPDATED',
    commandId: killCmd.id,
    deviceId,
    status: 'Executed',
    updatedDeviceStatus: 'Remediated',
    updatedDeviceRisk: 20,
    updatedOrgRisk: org?.riskScore || 24,
    timestamp: now
  });

  endpointDb.appendAudit(
    req.user!.email,
    orgId,
    'ENDPOINT_DEMO_REMEDIATED',
    `Scripted demo remediation executed: Terminated process demo_suspicious, forced user logout, de-escalated org risk to ${org?.riskScore || 24}, anchored ${patternCode} to DLT Block #${dltBlock.blockNumber}.`,
    deviceId
  );

  res.json({
    success: true,
    stage: 'REMEDIATED_AND_SHARED',
    deviceId,
    updatedDeviceStatus: 'Remediated',
    updatedOrgRisk: org?.riskScore || 24,
    threatPattern: existingPattern,
    dltBlock,
    peerEarlyWarning: hospCorr,
    message: 'Device remediated, org risk dropped, pattern sanitized, and peer institution alerted.'
  });
});

app.post('/api/demo/endpoint-reset', requireAuth, requireAdmin, requireDemoMode, (req: AuthenticatedRequest, res: Response) => {
  if (!AUTH_CONFIG.ENABLE_ENDPOINT_AGENT) {
    return res.status(404).json({ error: 'MODULE_DISABLED', message: 'Endpoint Agent module is disabled in this deployment.' });
  }

  const deviceId = 'DEV-BANK-01';
  const orgId = req.user!.orgId;

  // Restore device to Healthy
  endpointDb.updateDeviceStatus(deviceId, 'Healthy', 18);

  // Reset org risk to clean baseline
  const org = db.organizations[orgId];
  if (org) {
    org.riskBreakdown.authentication = 45;
    org.riskBreakdown.endpointSecurity = 38;
    org.riskTrend = 'FALLING';
    org.riskScore = 42;
  }

  // Clear detections
  endpointDetectionEngine.resetBaseline();

  wsHub.broadcastToAdmins(orgId, {
    type: 'DEVICE_UPDATED',
    deviceId,
    status: 'Healthy',
    risk: 18,
    updatedOrgRisk: 42,
    timestamp: new Date().toISOString()
  });

  res.json({
    success: true,
    message: 'Endpoint demo state restored cleanly to healthy baseline.'
  });
});

// 13. Investment Optimization API Endpoints (Admin SOC only, scoped to caller's org)
app.post('/api/investment-optimization', requireAuth, requireAdmin, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { budget, minCvss, knownExploitedOnly } = req.body || {};
    const result = await optimizeCyberInvestment({
      budget: budget !== undefined ? Number(budget) : 1000000,
      minCvss: minCvss ? Number(minCvss) : undefined,
      knownExploitedOnly: Boolean(knownExploitedOnly)
    });
    res.json(result);
  } catch (err: any) {
    console.error('Investment Optimization error:', err);
    res.status(500).json({ error: 'Failed to calculate investment optimization', details: err.message });
  }
});

app.get('/api/investment-optimization', requireAuth, requireAdmin, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const budget = req.query.budget ? Number(req.query.budget) : 1000000;
    const minCvss = req.query.minCvss ? Number(req.query.minCvss) : undefined;
    const knownExploitedOnly = req.query.knownExploitedOnly === 'true';

    const result = await optimizeCyberInvestment({
      budget,
      minCvss,
      knownExploitedOnly
    });
    res.json(result);
  } catch (err: any) {
    console.error('Investment Optimization error:', err);
    res.status(500).json({ error: 'Failed to calculate investment optimization', details: err.message });
  }
});

const server = http.createServer(app);

// Attach authenticated WebSocket channels: /ws/agent & /ws/admin
wsHub.attachToServer(server);

server.listen(Number(PORT), '0.0.0.0', async () => {
  console.log(`⚡ [CYBERGUARD GRID BACKEND] Server running on http://127.0.0.1:${PORT}`);
  console.log(`🔌 [WEBSOCKET HUB] Active endpoints: ws://127.0.0.1:${PORT}/ws/agent & ws://127.0.0.1:${PORT}/ws/admin`);
  // Verify MySQL database connection
  await vulnerabilityDb.testMysqlConnection();
  // Launch automated vulnerability intelligence scheduler
  syncService.startScheduler(30);
});
