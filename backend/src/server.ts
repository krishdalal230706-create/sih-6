import dotenv from 'dotenv';
dotenv.config();

import express, { Request, Response } from 'express';
import cors from 'cors';
import { db } from './models/db.js';
import { calculateOrganizationRisk } from './engine/riskEngine.js';
import { correlateThreatPatterns } from './engine/correlationEngine.js';
import { sanitizeIncidentToPattern } from './engine/privacyEngine.js';
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
      // Allow localhost in non-production
      if (process.env.NODE_ENV !== 'production' && (origin.includes('localhost') || origin.includes('127.0.0.1'))) {
        return callback(null, true);
      }
      return callback(new Error(`CORS error: Origin ${origin} not permitted.`));
    },
    credentials: true
  })
);
app.use(express.json());

// Security: In-memory sliding window rate limiting for all API routes
app.use('/api', generalApiLimiter);

// Logger middleware
app.use((req, res, next) => {
  console.log(`[API] ${req.method} ${req.path}`);
  next();
});

// Health check
app.get('/api/health', (req: Request, res: Response) => {
  res.json({ status: 'Operational', name: 'CyberGuard Grid API', version: '2.0.0-live-intel' });
});

// Vulnerability Intelligence API Routes
app.use('/api/vulnerabilities', vulnerabilityRouter);

// Sources & Synchronization Endpoints
app.get('/api/sources', async (req: Request, res: Response) => {
  try {
    const sources = await vulnerabilityDb.getSources();
    res.json({ sources });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to retrieve sources' });
  }
});

app.get('/api/sync/status', async (req: Request, res: Response) => {
  try {
    const status = await syncService.getStatus();
    res.json(status);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to retrieve sync status' });
  }
});

app.post('/api/sync/run', async (req: Request, res: Response) => {
  try {
    const status = await syncService.runSync({ force: req.body?.force });
    res.json(status);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to execute synchronization', details: err.message });
  }
});

// 1. Dashboard API
app.get('/api/dashboard', async (req: Request, res: Response) => {
  const org = db.getActiveOrganization();
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
    // Real live vulnerability data from database
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
    { time: '09:05', text: 'Phishing attack simulation completed for Demo Bank', type: 'SIMULATION' }
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

// 2. Organizations API
app.get('/api/organizations', (req: Request, res: Response) => {
  const list = Object.values(db.organizations).map((org) => {
    const incidents = db.incidents.filter((i) => i.orgId === org.id && i.status !== 'Resolved');
    return {
      ...org,
      calculatedRisk: calculateOrganizationRisk(org, incidents.length).overallRiskScore
    };
  });
  res.json({ organizations: list, activeOrgId: db.activeOrgId });
});

app.get('/api/organizations/:id', (req: Request, res: Response) => {
  const org = db.organizations[req.params.id];
  if (!org) return res.status(404).json({ error: 'Organization not found' });
  const incidents = db.incidents.filter((i) => i.orgId === org.id && i.status !== 'Resolved');
  const calculatedRisk = calculateOrganizationRisk(org, incidents.length);
  res.json({ organization: org, calculatedRisk });
});

app.post('/api/organizations/switch', validateRequestBody({ orgId: { type: 'string', required: true, minLength: 1, maxLength: 50 } }), (req: Request, res: Response) => {
  const { orgId } = req.body;
  if (!db.organizations[orgId]) return res.status(404).json({ error: 'Organization not found' });
  db.activeOrgId = orgId;
  res.json({ success: true, activeOrganization: db.getActiveOrganization() });
});

app.put('/api/organizations/:id', (req: Request, res: Response) => {
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

// 3. Cyber Risk API
app.get('/api/risk', (req: Request, res: Response) => {
  const org = db.getActiveOrganization();
  const incidents = db.incidents.filter((i) => i.orgId === org.id && i.status !== 'Resolved');
  const riskResult = calculateOrganizationRisk(org, incidents.length);
  res.json({ organization: org, riskResult });
});

app.get('/api/risk/:organizationId', (req: Request, res: Response) => {
  const org = db.organizations[req.params.organizationId] || db.getActiveOrganization();
  const incidents = db.incidents.filter((i) => i.orgId === org.id && i.status !== 'Resolved');
  const riskResult = calculateOrganizationRisk(org, incidents.length);
  res.json({ organization: org, riskResult });
});

app.post('/api/risk/recalculate', (req: Request, res: Response) => {
  const { organizationId } = req.body;
  const org = db.organizations[organizationId] || db.getActiveOrganization();
  const incidents = db.incidents.filter((i) => i.orgId === org.id && i.status !== 'Resolved');
  const newRisk = calculateOrganizationRisk(org, incidents.length);
  org.riskScore = newRisk.overallRiskScore;
  res.json({ success: true, updatedRisk: newRisk });
});

// Direct Remediation Endpoint for Green Button in Attack Simulator & Attack Path
app.post('/api/risk/remediate-weak-point', (req: Request, res: Response) => {
  const org = db.getActiveOrganization();
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

// 4. Attack Simulator API
app.get('/api/attack-scenarios', (req: Request, res: Response) => {
  res.json({ scenarios: db.attackScenarios });
});

app.post('/api/attack-scenarios/:id/simulate', (req: Request, res: Response) => {
  const scenario = db.attackScenarios.find((s) => s.id === req.params.id) || db.attackScenarios[0];
  const org = db.getActiveOrganization();

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

// 5. Threat Detection & Telemetry Stream API
app.get('/api/telemetry', (req: Request, res: Response) => {
  res.json({ telemetryStream: db.telemetryStream });
});

app.post('/api/telemetry/simulate', (req: Request, res: Response) => {
  const { eventType, details } = req.body;
  const newEvent: TelemetryEvent = {
    id: `tel-${Date.now()}`,
    timestamp: new Date().toTimeString().slice(0, 8),
    eventType: eventType || 'PRIVILEGE_ESCALATION',
    sourceIp: '198.51.100.42',
    user: 'admin@demobank.com',
    deviceId: 'DEV-UNKNOWN-889',
    severity: 'CRITICAL',
    details: details || 'Simulated privilege escalation event injected from command center.'
  };

  db.telemetryStream.unshift(newEvent);

  // Update org risk state dynamically!
  const org = db.getActiveOrganization();
  const oldRisk = org.riskScore;
  org.riskScore = Math.min(98, org.riskScore + 13);
  org.riskTrend = 'RISING';
  org.riskBreakdown.authentication = Math.min(99, org.riskBreakdown.authentication + 10);

  res.json({
    event: newEvent,
    threatDetected: {
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

// 6. Incident Management API
app.get('/api/incidents', (req: Request, res: Response) => {
  const orgId = req.query.orgId as string;
  const list = orgId ? db.incidents.filter((i) => i.orgId === orgId) : db.incidents;
  res.json({ incidents: list });
});

app.get('/api/incidents/:id', (req: Request, res: Response) => {
  const inc = db.incidents.find((i) => i.id === req.params.id || i.incidentId === req.params.id);
  if (!inc) return res.status(404).json({ error: 'Incident not found' });
  const actions = db.responseActions.filter((a) => a.incidentId === inc.id);
  res.json({ incident: inc, responseActions: actions });
});

app.post('/api/incidents/:id/respond', (req: Request, res: Response) => {
  const { actionId, markStatus } = req.body;
  const action = db.responseActions.find((a) => a.id === actionId) || db.responseActions[0];
  const inc = db.incidents.find((i) => i.id === req.params.id || i.incidentId === req.params.id);

  if (!action) return res.status(404).json({ error: 'Response action not found' });

  action.status = markStatus || 'Completed';

  // Lower organization risk score appropriately!
  const org = db.organizations[action.orgId] || db.getActiveOrganization();
  const oldScore = org.riskScore;
  const reduction = action.estimatedRiskReduction;
  if (action.status === 'Completed') {
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
      newScore: org.riskScore,
      pointsReduced: reduction
    }
  });
});

// 7. Response Center API
app.get('/api/response-actions', (req: Request, res: Response) => {
  const orgId = (req.query.orgId as string) || db.activeOrgId;
  // Return all actions if 'all' is requested (client filters by org)
  const actions = orgId === 'all' ? db.responseActions : db.responseActions.filter((a) => a.orgId === orgId);
  res.json({ responseActions: actions });
});

// 8. Privacy Engine API
app.post('/api/privacy/sanitize', (req: Request, res: Response) => {
  const { incidentId } = req.body;
  const inc = db.incidents.find((i) => i.id === incidentId || i.incidentId === incidentId) || db.incidents[0];

  const result = sanitizeIncidentToPattern(inc);

  // Check if pattern already added
  let existingPattern = db.threatPatterns.find((tp) => tp.hash === result.sanitizedPattern.patternHash);
  if (!existingPattern) {
    existingPattern = {
      id: `tp-${Date.now()}`,
      patternCode: result.sanitizedPattern.threatPatternId,
      originOrgId: inc.orgId,
      originOrgName: db.organizations[inc.orgId]?.name || 'Demo Bank',
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

// 9. Threat Intelligence Library API
app.get('/api/threat-intelligence', (req: Request, res: Response) => {
  res.json({ threatPatterns: db.threatPatterns });
});

app.post('/api/threat-intelligence/compare', (req: Request, res: Response) => {
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

// 10. Collaborative Network API
app.get('/api/network', (req: Request, res: Response) => {
  const nodes = Object.values(db.organizations).map((o) => ({
    id: o.id,
    name: o.name,
    type: o.type,
    riskScore: o.riskScore,
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

app.post('/api/network/broadcast', (req: Request, res: Response) => {
  const { threatCode, targetOrgId, broadcastScope } = req.body;
  const pattern = db.threatPatterns.find((tp) => tp.patternCode === threatCode) || db.threatPatterns[0];
  const sourceOrg = db.organizations[pattern.originOrgId] || db.getActiveOrganization();

  // Peer organizations in the mesh
  const peerOrgs = Object.values(db.organizations).filter((o) => o.id !== sourceOrg.id);

  // Correlate across each peer organization in the mesh
  const meshPropagation = peerOrgs.map((peer) => {
    let targetEvents: string[] = [];
    if (peer.id === 'org-2') {
      // City Hospital - high sequence similarity (92%)
      targetEvents = ['FAILED_LOGIN', 'NEW_DEVICE', 'UNUSUAL_LOCATION', 'PRIVILEGE_ESCALATION', 'LARGE_DATA_TRANSFER'];
    } else if (peer.id === 'org-4') {
      // FinTech Corp - moderate-high similarity (85%)
      targetEvents = ['FAILED_LOGIN', 'NEW_DEVICE', 'PRIVILEGE_ESCALATION', 'LARGE_DATA_TRANSFER'];
    } else if (peer.id === 'org-3') {
      // State University - moderate similarity (67%)
      targetEvents = ['FAILED_LOGIN', 'UNUSUAL_LOCATION', 'DATA_ACCESS'];
    } else {
      // Apex Energy / others - baseline similarity (38%)
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
    consensusValidators: ['Demo Bank', 'City Hospital', 'State University', 'FinTech Corp'],
    meshPropagation
  });
});

// 11. DLT Trust Ledger API
app.get('/api/ledger', (req: Request, res: Response) => {
  res.json({ ledgerRecords: db.ledgerRecords });
});

app.post('/api/ledger/add', strictMutationLimiter, validateRequestBody({ threatId: { type: 'string', required: true, minLength: 2, maxLength: 50 } }), (req: Request, res: Response) => {
  const { threatId, reporter, hash, validators, status } = req.body;
  if (!threatId) return res.status(400).json({ error: 'threatId required' });
  const newBlock = addLedgerBlock(
    threatId || 'TH-CUSTOM',
    reporter || db.getActiveOrganization().name,
    hash || `custom-hash-${Date.now()}`,
    validators,
    status
  );
  res.json({ success: true, block: newBlock, ledgerRecords: db.ledgerRecords });
});

app.post('/api/ledger/verify', (req: Request, res: Response) => {
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

app.post('/api/ledger/validate', (req: Request, res: Response) => {
  const { blockNumber, validatorOrg } = req.body;
  const num = Number(blockNumber) || 10421;
  const validator = validatorOrg || db.getActiveOrganization().name;
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

app.post('/api/ledger/tamper', strictMutationLimiter, (req: Request, res: Response) => {
  const { blockNumber, newThreatId } = req.body;
  const targetNum = Number(blockNumber) || 10420;
  const result = tamperLedgerRecord(targetNum, newThreatId);

  res.json({
    ...result,
    ledgerRecords: db.ledgerRecords
  });
});

app.post('/api/ledger/reset', strictMutationLimiter, (req: Request, res: Response) => {
  const baseline = restoreLedgerBaseline();
  res.json({
    success: true,
    ledgerRecords: baseline,
    message: 'DLT Ledger successfully restored to valid baseline state.'
  });
});

// 12. Automated Demo Mode Step Controller & Reset
app.post('/api/demo/reset', strictMutationLimiter, (req: Request, res: Response) => {
  db.resetToBaseline();
  res.json({
    success: true,
    message: 'CyberGuard Grid demo state successfully reset to clean baseline.',
    activeOrg: db.getActiveOrganization(),
    organizations: Object.values(db.organizations),
    ledgerRecords: db.ledgerRecords
  });
});

app.post('/api/demo/step', validateRequestBody({ step: { type: 'number', required: true, min: 1, max: 4 } }), (req: Request, res: Response) => {
  const { step } = req.body;
  const currentStep = Number(step) || 1;

  if (currentStep === 1) {
    // Day 1: Normal Baseline Posture (Risk Score ~42, low alerts, green indicators)
    db.activeOrgId = 'org-1';
    db.organizations['org-1'].riskScore = 42;
    db.organizations['org-1'].riskTrend = 'FALLING';
    db.organizations['org-1'].riskBreakdown = {
      authentication: 45,
      networkSecurity: 40,
      dataSecurity: 42,
      endpointSecurity: 38,
      userRisk: 45
    };
    const inc = db.incidents.find((i) => i.id === 'inc-1');
    if (inc) inc.status = 'Contained';
  } else if (currentStep === 2) {
    // Day 2: Phishing & Credential Access / Lateral Movement (Failed logins, new device, risk jumps to 78)
    db.organizations['org-1'].riskScore = 78;
    db.organizations['org-1'].riskTrend = 'RISING';
    db.organizations['org-1'].riskBreakdown.authentication = 82;
    db.organizations['org-1'].riskBreakdown.endpointSecurity = 74;
    const inc = db.incidents.find((i) => i.id === 'inc-1');
    if (inc) inc.status = 'Detected';
  } else if (currentStep === 3) {
    // Day 3: Privilege Escalation & Cross-Org Early Warning (Risk jumps to 91 Critical, pattern TH-7821 sanitized, DLT Block committed, peer mesh alerted)
    db.organizations['org-1'].riskScore = 91;
    db.organizations['org-1'].riskTrend = 'RISING';
    db.organizations['org-1'].riskBreakdown.authentication = 95;
    db.organizations['org-1'].riskBreakdown.dataSecurity = 92;
    db.organizations['org-2'].riskScore = 82;
    db.organizations['org-2'].riskTrend = 'RISING';
    const inc = db.incidents.find((i) => i.id === 'inc-1');
    if (inc) inc.status = 'Investigating';
  } else if (currentStep === 4) {
    // Day 4: Containment & Remediation (Remediate weak point, FIDO2 enforced, risk falls to 24, ledger validated)
    db.organizations['org-1'].riskScore = 24;
    db.organizations['org-1'].riskTrend = 'FALLING';
    db.organizations['org-1'].riskBreakdown = {
      authentication: 22,
      networkSecurity: 26,
      dataSecurity: 25,
      endpointSecurity: 20,
      userRisk: 27
    };
    const inc = db.incidents.find((i) => i.id === 'inc-1');
    if (inc) inc.status = 'Resolved';
    const action = db.responseActions.find((a) => a.orgId === 'org-1');
    if (action) action.status = 'Completed';
  }

  res.json({
    step: currentStep,
    activeOrg: db.getActiveOrganization(),
    hospitalBOrg: db.organizations['org-2'],
    incidents: db.incidents,
    threatPatterns: db.threatPatterns,
    latestLedgerBlock: db.ledgerRecords[db.ledgerRecords.length - 1]
  });
});

// 13. Investment Optimization API Endpoints
app.post('/api/investment-optimization', async (req: Request, res: Response) => {
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

app.get('/api/investment-optimization', async (req: Request, res: Response) => {
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

app.listen(Number(PORT), '0.0.0.0', async () => {
  console.log(`⚡ [CYBERGUARD GRID BACKEND] Server running on http://127.0.0.1:${PORT}`);
  // Verify MySQL database connection
  await vulnerabilityDb.testMysqlConnection();
  // Launch automated vulnerability intelligence scheduler
  syncService.startScheduler(30);
});
