import { Router, Response } from 'express';
import crypto from 'crypto';
import { z } from 'zod';
import { endpointDb, BankAssetRecord, BankSecurityEventRecord } from '../db/endpointDb.js';
import { requireAuth, requireAdmin, AuthenticatedRequest } from '../middleware/authMiddleware.js';
import { BankAsset, BankSecurityEvent } from '../types.js';

export const bankAssetRouter = Router();

function toBankAsset(record: BankAssetRecord): BankAsset {
  return {
    id: record.id,
    orgId: record.org_id,
    name: record.name,
    category: record.category,
    description: record.description,
    criticality: record.criticality,
    ipOrIdentifier: record.ip_or_identifier,
    technologyStack: record.technology_stack,
    ownerDepartment: record.owner_department,
    securityStatus: record.security_status,
    associatedVulnsCount: record.associated_vulns_count,
    lastAssessmentDate: record.last_assessment_date,
    riskScore: record.risk_score,
    createdAt: record.created_at,
    updatedAt: record.updated_at
  };
}

function toBankSecurityEvent(record: BankSecurityEventRecord & { affected_asset_name?: string }): BankSecurityEvent {
  return {
    id: record.id,
    orgId: record.org_id,
    affectedAssetId: record.affected_asset_id,
    affectedAssetName: record.affected_asset_name,
    eventCategory: record.event_category,
    severity: record.severity,
    timestamp: record.timestamp,
    description: record.description,
    detectionSource: record.detection_source,
    investigationStatus: record.investigation_status,
    recommendedAction: record.recommended_action
  };
}

const createAssetSchema = z.object({
  name: z.string().min(2).max(120),
  category: z.string().min(2).max(80),
  description: z.string().min(5).max(500),
  criticality: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
  ipOrIdentifier: z.string().min(3).max(100),
  technologyStack: z.string().min(2).max(150),
  ownerDepartment: z.string().min(2).max(100),
  securityStatus: z.enum(['HEALTHY', 'DEGRADED', 'AT_RISK', 'COMPROMISED', 'MAINTENANCE']).default('HEALTHY'),
  associatedVulnsCount: z.number().int().min(0).default(0),
  riskScore: z.number().int().min(0).max(100).default(25)
});

const updateAssetSchema = createAssetSchema.partial();

const createEventSchema = z.object({
  affectedAssetId: z.string().min(1),
  eventCategory: z.string().min(2).max(100),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
  description: z.string().min(5).max(500),
  detectionSource: z.string().min(2).max(100),
  investigationStatus: z.enum(['NEW', 'INVESTIGATING', 'CONTAINED', 'RESOLVED']).default('NEW'),
  recommendedAction: z.string().min(2).max(500)
});

// GET /api/bank-assets - List all assets for caller's organization
bankAssetRouter.get('/', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const orgId = user.orgId || 'org-1';
  const records = endpointDb.getBankAssets(orgId);
  const assets = records.map(toBankAsset);
  return res.json({ assets, count: assets.length });
});

// GET /api/bank-assets/events - List security events with filtering
bankAssetRouter.get('/events', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const orgId = user.orgId || 'org-1';
  const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 50;
  const severity = req.query.severity as string | undefined;
  const assetId = req.query.assetId as string | undefined;
  const status = req.query.status as string | undefined;

  const records = endpointDb.getBankSecurityEvents(orgId, isNaN(limit) ? 50 : limit, {
    severity,
    assetId,
    status
  });

  const events = records.map(toBankSecurityEvent);
  return res.json({ events, count: events.length });
});

// GET /api/bank-assets/:id - Get single asset details
bankAssetRouter.get('/:id', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const orgId = user.orgId || 'org-1';
  const record = endpointDb.getBankAssetById(req.params.id);

  if (!record || record.org_id !== orgId) {
    return res.status(404).json({ error: 'ASSET_NOT_FOUND', message: 'Banking asset not found or unauthorized.' });
  }

  return res.json({ asset: toBankAsset(record) });
});

// POST /api/bank-assets - Create new banking asset (Admin only)
bankAssetRouter.post('/', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const orgId = user.orgId || 'org-1';

  const parseResult = createAssetSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({ error: 'VALIDATION_FAILED', details: parseResult.error.format() });
  }

  const data = parseResult.data;
  const id = `asset-${crypto.randomBytes(4).toString('hex')}`;
  const now = new Date().toISOString();

  const record: BankAssetRecord = {
    id,
    org_id: orgId,
    name: data.name,
    category: data.category,
    description: data.description,
    criticality: data.criticality,
    ip_or_identifier: data.ipOrIdentifier,
    technology_stack: data.technologyStack,
    owner_department: data.ownerDepartment,
    security_status: data.securityStatus,
    associated_vulns_count: data.associatedVulnsCount,
    last_assessment_date: now.slice(0, 10),
    risk_score: data.riskScore,
    created_at: now,
    updated_at: now
  };

  endpointDb.saveBankAsset(record);
  endpointDb.appendAudit(user.email, orgId, 'BANK_ASSET_CREATED', `Created banking asset ${record.name} (${record.id})`);

  return res.status(201).json({ asset: toBankAsset(record) });
});

// PUT /api/bank-assets/:id - Update banking asset (Admin only)
bankAssetRouter.put('/:id', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const orgId = user.orgId || 'org-1';

  const existing = endpointDb.getBankAssetById(req.params.id);
  if (!existing || existing.org_id !== orgId) {
    return res.status(404).json({ error: 'ASSET_NOT_FOUND', message: 'Banking asset not found or unauthorized.' });
  }

  const parseResult = updateAssetSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({ error: 'VALIDATION_FAILED', details: parseResult.error.format() });
  }

  const data = parseResult.data;
  const updates: Partial<BankAssetRecord> = {};
  if (data.name !== undefined) updates.name = data.name;
  if (data.category !== undefined) updates.category = data.category;
  if (data.description !== undefined) updates.description = data.description;
  if (data.criticality !== undefined) updates.criticality = data.criticality;
  if (data.ipOrIdentifier !== undefined) updates.ip_or_identifier = data.ipOrIdentifier;
  if (data.technologyStack !== undefined) updates.technology_stack = data.technologyStack;
  if (data.ownerDepartment !== undefined) updates.owner_department = data.ownerDepartment;
  if (data.securityStatus !== undefined) updates.security_status = data.securityStatus;
  if (data.associatedVulnsCount !== undefined) updates.associated_vulns_count = data.associatedVulnsCount;
  if (data.riskScore !== undefined) updates.risk_score = data.riskScore;

  const updatedRecord = endpointDb.updateBankAsset(req.params.id, updates);
  if (!updatedRecord) {
    return res.status(500).json({ error: 'UPDATE_FAILED', message: 'Could not update asset.' });
  }

  endpointDb.appendAudit(user.email, orgId, 'BANK_ASSET_UPDATED', `Updated banking asset ${updatedRecord.name} (${updatedRecord.id})`);

  return res.json({ asset: toBankAsset(updatedRecord) });
});

// DELETE /api/bank-assets/:id - Delete banking asset (Admin only)
bankAssetRouter.delete('/:id', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const orgId = user.orgId || 'org-1';

  const existing = endpointDb.getBankAssetById(req.params.id);
  if (!existing || existing.org_id !== orgId) {
    return res.status(404).json({ error: 'ASSET_NOT_FOUND', message: 'Banking asset not found or unauthorized.' });
  }

  endpointDb.deleteBankAsset(req.params.id);
  endpointDb.appendAudit(user.email, orgId, 'BANK_ASSET_DELETED', `Deleted banking asset ${existing.name} (${existing.id})`);

  return res.json({ success: true, message: `Asset ${existing.name} deleted successfully.` });
});

// POST /api/bank-assets/events - Log a new security event
bankAssetRouter.post('/events', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const orgId = user.orgId || 'org-1';

  const parseResult = createEventSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({ error: 'VALIDATION_FAILED', details: parseResult.error.format() });
  }

  const data = parseResult.data;
  const asset = endpointDb.getBankAssetById(data.affectedAssetId);
  if (!asset || asset.org_id !== orgId) {
    return res.status(400).json({ error: 'INVALID_ASSET', message: 'Target asset does not exist in your organization.' });
  }

  const eventId = `evt-${crypto.randomBytes(4).toString('hex')}`;
  const now = new Date().toISOString();

  const eventRecord: BankSecurityEventRecord = {
    id: eventId,
    org_id: orgId,
    affected_asset_id: data.affectedAssetId,
    event_category: data.eventCategory,
    severity: data.severity,
    timestamp: now,
    description: data.description,
    detection_source: data.detectionSource,
    investigation_status: data.investigationStatus,
    recommended_action: data.recommendedAction
  };

  endpointDb.saveBankSecurityEvent(eventRecord);

  // If critical/high severity, optionally mark asset security status
  if (data.severity === 'CRITICAL' && asset.security_status !== 'COMPROMISED') {
    endpointDb.updateBankAsset(asset.id, { security_status: 'COMPROMISED', risk_score: Math.min(100, asset.risk_score + 25) });
  } else if (data.severity === 'HIGH' && asset.security_status === 'HEALTHY') {
    endpointDb.updateBankAsset(asset.id, { security_status: 'AT_RISK', risk_score: Math.min(100, asset.risk_score + 15) });
  }

  endpointDb.appendAudit(user.email, orgId, 'BANK_SECURITY_EVENT_LOGGED', `Security event ${eventId} (${data.eventCategory} - ${data.severity}) on ${asset.name}`);

  return res.status(201).json({ event: toBankSecurityEvent({ ...eventRecord, affected_asset_name: asset.name }) });
});

// PATCH /api/bank-assets/events/:id - Update investigation status
bankAssetRouter.patch('/events/:id', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const orgId = user.orgId || 'org-1';

  const statusSchema = z.object({
    status: z.enum(['NEW', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'])
  });

  const parseResult = statusSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({ error: 'VALIDATION_FAILED', message: 'Invalid investigation status.' });
  }

  const existing = endpointDb.getBankSecurityEventById(req.params.id);
  if (!existing || existing.org_id !== orgId) {
    return res.status(404).json({ error: 'EVENT_NOT_FOUND', message: 'Security event not found or unauthorized.' });
  }

  const updated = endpointDb.updateBankSecurityEventStatus(req.params.id, parseResult.data.status);
  endpointDb.appendAudit(user.email, orgId, 'BANK_EVENT_STATUS_UPDATED', `Updated event ${req.params.id} status to ${parseResult.data.status}`);

  return res.json({ event: updated ? toBankSecurityEvent(updated) : null });
});

// POST /api/bank-assets/reset-baseline - Admin re-seeding baseline
bankAssetRouter.post('/reset-baseline', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  endpointDb.seedBankingDataIfEmpty();
  endpointDb.appendAudit(user.email, user.orgId, 'BANK_BASELINE_RESET', 'Demo Bank assets and security events reset to baseline.');
  const assets = endpointDb.getBankAssets(user.orgId).map(toBankAsset);
  return res.json({ success: true, assets, count: assets.length });
});

// GET /api/bank-assets/enclaves - Banking Security Enclave Architecture Topology
bankAssetRouter.get('/enclaves', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const orgId = user.orgId || 'org-1';
  const records = endpointDb.getBankAssets(orgId).map(toBankAsset);

  // Group into 4 Real-World Banking Enclaves
  const enclaves = [
    {
      id: 'enclave-dmz',
      name: 'Zone 1: Perimeter DMZ',
      description: 'External-facing customer portals with WAF rate-limiting and reverse proxy inspection.',
      securityLevel: 'Public DMZ',
      ingressPolicy: 'Strict HTTPS (Port 443) via Cloudflare & Palo Alto NGFW',
      assets: records.filter((a) => ['asset-netbank', 'asset-mobile'].includes(a.id)),
      telemetry: {
        activeConnections: 1420,
        requestsPerSec: 320,
        blockedProbesPerMin: 85
      }
    },
    {
      id: 'enclave-payment',
      name: 'Zone 2: Payment Switch & NPCI Gateway',
      description: 'High-throughput clearing subnet interfacing with NPCI NFS and UPI 2.0 settlement.',
      securityLevel: 'PCI-DSS / RBI Payment Enclave',
      ingressPolicy: 'Mutual TLS (mTLS) & Hardware Token Authentication',
      assets: records.filter((a) => ['asset-payment', 'asset-atm'].includes(a.id)),
      telemetry: {
        currentTps: 185,
        avgLatencyMs: 14,
        fraudVelocityStatus: records.find((a) => a.id === 'asset-payment')?.securityStatus === 'COMPROMISED' ? 'ALERT' : 'NORMAL'
      }
    },
    {
      id: 'enclave-core',
      name: 'Zone 3: Private Core Banking Enclave',
      description: 'Zero direct internet access. Finacle Core ledger, Thales Luna HSM, and Oracle RAC CIF.',
      securityLevel: 'Tier-1 Air-Gapped Internal',
      ingressPolicy: 'Internal Microsegmentation with DB Activity Monitoring',
      assets: records.filter((a) => ['asset-cbs', 'asset-auth', 'asset-custdb'].includes(a.id)),
      telemetry: {
        activeLedgerTransactions: 2450,
        hsmVerificationTps: 120,
        integrityStatus: 'VERIFIED'
      }
    },
    {
      id: 'enclave-internal',
      name: 'Zone 4: Operations & Disaster Recovery',
      description: 'Regional branch workstation fleets and off-site Hyderabad synchronous DR replication.',
      securityLevel: 'Restricted Branch & BC/DR',
      ingressPolicy: 'IPsec SD-WAN VPN with Immutable Backup Storage',
      assets: records.filter((a) => ['asset-workstations', 'asset-network', 'asset-dr'].includes(a.id)),
      telemetry: {
        branchEndpointsOnline: 24,
        drReplicationLagSeconds: 0.8,
        storageImmutability: 'WORM Locked'
      }
    }
  ];

  return res.json({ enclaves });
});

// POST /api/bank-assets/simulate-scenario - Live Demo Injection Bridge
bankAssetRouter.post('/simulate-scenario', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const orgId = user.orgId || 'org-1';
  const scenarioId = req.body.scenarioId || 'scenario-3';

  interface ScenarioMapping {
    assetId: string;
    category: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
    description: string;
    source: string;
    action: string;
    statusEffect: 'COMPROMISED' | 'AT_RISK';
    riskDelta: number;
  }

  const mappings: Record<string, ScenarioMapping> = {
    'scenario-1': {
      assetId: 'asset-workstations',
      category: 'Phishing & Account Takeover',
      severity: 'HIGH',
      description: 'Spear-phishing credential theft simulation: Teller workstation elevated session token replayed.',
      source: 'Identity Threat Sentry',
      action: 'Revoke active sessions and enforce FIDO2 hardware token verification.',
      statusEffect: 'AT_RISK',
      riskDelta: 22
    },
    'scenario-2': {
      assetId: 'asset-netbank',
      category: 'Credential Stuffing Burst',
      severity: 'HIGH',
      description: 'Distributed proxy botnet simulation: 1,840 failed customer logins / min targeting Internet Banking.',
      source: 'WAF Rate Limiter',
      action: 'Deploy immediate CAPTCHA challenge and IP CIDR velocity throttling.',
      statusEffect: 'AT_RISK',
      riskDelta: 25
    },
    'scenario-3': {
      assetId: 'asset-payment',
      category: 'UPI Gateway Micro-Debit Fraud',
      severity: 'CRITICAL',
      description: 'High-frequency micro-debit anomaly simulation: 420 micro-debits/min to suspect merchant VPA.',
      source: 'UPI AI Sentry',
      action: 'Apply instant settlement freeze and throttle suspect merchant endpoint.',
      statusEffect: 'COMPROMISED',
      riskDelta: 35
    },
    'scenario-4': {
      assetId: 'asset-workstations',
      category: 'Controlled Ransomware Canary Tripwire',
      severity: 'CRITICAL',
      description: 'Non-destructive ransomware canary file rename simulation on Branch Workstation subnet.',
      source: 'Behavioral EDR Agent',
      action: 'Host isolated from network; verify immutable snapshot rollback.',
      statusEffect: 'COMPROMISED',
      riskDelta: 30
    },
    'scenario-5': {
      assetId: 'asset-custdb',
      category: 'Insider Threat CIF Export',
      severity: 'HIGH',
      description: 'Off-hours bulk CIF record query simulation (10,000+ entries at 02:14 AM IST).',
      source: 'Database Activity Monitor (DAM)',
      action: 'Verify operational authorization and suspend unapproved query batches.',
      statusEffect: 'AT_RISK',
      riskDelta: 24
    },
    'scenario-6': {
      assetId: 'asset-cbs',
      category: 'Third-Party Dependency Vulnerability',
      severity: 'HIGH',
      description: 'Supply chain CVE alert simulation in embedded ISO 8583 banking library.',
      source: 'SBOM Dependency Auditor',
      action: 'Deploy WAF virtual patch signature to drop exploit attempts.',
      statusEffect: 'AT_RISK',
      riskDelta: 20
    }
  };

  const map = mappings[scenarioId] || mappings['scenario-3'];
  const asset = endpointDb.getBankAssetById(map.assetId);
  if (!asset) {
    return res.status(404).json({ error: 'ASSET_NOT_FOUND', message: 'Target asset does not exist.' });
  }

  // Update asset
  const newRiskScore = Math.min(100, asset.risk_score + map.riskDelta);
  endpointDb.updateBankAsset(asset.id, {
    security_status: map.statusEffect,
    risk_score: newRiskScore
  });

  // Inject Event
  const eventId = `evt-sim-${crypto.randomBytes(3).toString('hex')}`;
  const now = new Date().toISOString();
  const eventRecord: BankSecurityEventRecord = {
    id: eventId,
    org_id: orgId,
    affected_asset_id: asset.id,
    event_category: map.category,
    severity: map.severity,
    timestamp: now,
    description: map.description,
    detection_source: map.source,
    investigation_status: 'NEW',
    recommended_action: map.action
  };
  endpointDb.saveBankSecurityEvent(eventRecord);

  endpointDb.appendAudit(user.email, orgId, 'ATTACK_SIMULATION_INJECTED', `Injected ${scenarioId} (${map.category}) on ${asset.name}. Risk spiked +${map.riskDelta}.`);

  return res.status(201).json({
    success: true,
    scenarioId,
    event: toBankSecurityEvent({ ...eventRecord, affected_asset_name: asset.name }),
    affectedAsset: toBankAsset(endpointDb.getBankAssetById(asset.id)!),
    riskSpike: map.riskDelta
  });
});

// POST /api/bank-assets/remediate-incident - Live Demo Containment & Rollback
bankAssetRouter.post('/remediate-incident', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const orgId = user.orgId || 'org-1';
  const { assetId, eventId } = req.body;

  if (assetId) {
    const asset = endpointDb.getBankAssetById(assetId);
    if (asset) {
      const baselineRisk = asset.criticality === 'CRITICAL' ? 25 : 30;
      endpointDb.updateBankAsset(asset.id, {
        security_status: 'HEALTHY',
        risk_score: baselineRisk
      });
      endpointDb.appendAudit(user.email, orgId, 'ASSET_REMEDIATED', `Remediated ${asset.name}: status restored to HEALTHY (Risk: ${baselineRisk})`);
    }
  } else {
    // Restore all banking assets to healthy baseline postures
    const allAssets = endpointDb.getBankAssets(orgId);
    for (const a of allAssets) {
      if (a.security_status === 'COMPROMISED' || a.security_status === 'AT_RISK') {
        endpointDb.updateBankAsset(a.id, {
          security_status: 'HEALTHY',
          risk_score: a.criticality === 'CRITICAL' ? 25 : 30
        });
      }
    }
  }

  if (eventId) {
    endpointDb.updateBankSecurityEventStatus(eventId, 'RESOLVED');
  } else {
    // Resolve recent events
    const recent = endpointDb.getBankSecurityEvents(orgId, 10, { status: 'NEW' });
    for (const r of recent) {
      endpointDb.updateBankSecurityEventStatus(r.id, 'RESOLVED');
    }
  }

  endpointDb.appendAudit(user.email, orgId, 'PLAYBOOK_EXECUTED', 'Demo Bank SOC Playbook executed. Risk posture returned to safe baseline.');

  return res.json({
    success: true,
    message: 'Playbook successfully executed. Threat neutralized and asset restored to Healthy baseline.'
  });
});

// RBI Compliance In-Memory / Dynamic State Store for Demo Bank
let rbiControlOverrides: Record<string, 'COMPLIANT' | 'PARTIAL' | 'NON_COMPLIANT'> = {};

// GET /api/bank-assets/rbi-compliance - RBI Cyber Security Framework (CSF) Scorecard
bankAssetRouter.get('/rbi-compliance', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const orgId = user.orgId || 'org-1';
  const assets = endpointDb.getBankAssets(orgId);

  const paymentCompromised = assets.some((a) => a.id === 'asset-payment' && a.security_status === 'COMPROMISED');
  const netbankAtRisk = assets.some((a) => a.id === 'asset-netbank' && (a.security_status === 'AT_RISK' || a.security_status === 'COMPROMISED'));

  const baseControls = [
    {
      id: 'RBI-CSF-01',
      category: 'Network Segmentation & Enclave Isolation',
      name: 'Core Banking System (CBS) Physical/Logical Enclave Isolation',
      mandate: 'RBI Master Directions on IT Governance - Section 4.2',
      description: 'Finacle Core Banking System must reside in an air-gapped internal enclave with zero direct public ingress.',
      status: rbiControlOverrides['RBI-CSF-01'] || 'COMPLIANT',
      evidence: 'Zone 3 Private Enclave isolated via Palo Alto NGFW & strict mTLS boundary.',
      remediationAction: 'Maintain strict microsegmentation rules on CBS VLAN.'
    },
    {
      id: 'RBI-CSF-02',
      category: 'Cryptographic Security & Key Management',
      name: 'Hardware Security Module (HSM) Dedicated Cryptographic Key Verification',
      mandate: 'RBI Cyber Security Framework Annex-1 (HSM Controls)',
      description: 'PIN blocks, card CVV verification, and PKI digital certificates must be executed strictly within FIPS 140-2 Level 3 HSM.',
      status: rbiControlOverrides['RBI-CSF-02'] || 'COMPLIANT',
      evidence: 'Thales Luna HSM cluster integrated with Keycloak PKI at 10.10.1.12.',
      remediationAction: 'Perform routine quarterly HSM key rotation verification.'
    },
    {
      id: 'RBI-CSF-03',
      category: 'Access Control & Authentication',
      name: 'Mandatory Multi-Factor (FIDO2/WebAuthn) for Privileged Banking Access',
      mandate: 'RBI CSITE Circular 2021/89 - Identity Governance',
      description: 'All teller, branch manager, and SOC administrator portals must enforce phishing-resistant hardware MFA.',
      status: rbiControlOverrides['RBI-CSF-03'] || 'COMPLIANT',
      evidence: 'FIDO2 WebAuthn & biometric MPIN enforced across core management interfaces.',
      remediationAction: 'Audit active branch teller sessions and revoke non-FIDO2 tokens.'
    },
    {
      id: 'RBI-CSF-04',
      category: 'Customer Data Protection & Privacy',
      name: 'Customer Information File (CIF) Encryption at Rest (AES-256) & Transit (TLS 1.3)',
      mandate: 'RBI Master Directions Section 7 - Customer Data Protection',
      description: 'Aadhaar, PAN, account balances, and KYC PII must be encrypted using AES-256 with zero cleartext logging.',
      status: rbiControlOverrides['RBI-CSF-04'] || 'COMPLIANT',
      evidence: 'Oracle RAC 19c Transparent Data Encryption (TDE) active with AES-256.',
      remediationAction: 'Verify masking rules on teller workstation CSV exports.'
    },
    {
      id: 'RBI-CSF-05',
      category: 'Continuous SOC Telemetry & Monitoring',
      name: '24x7 Security Operations Center (SOC) Real-Time Alerting',
      mandate: 'RBI Cyber Security Framework Section 3.1 - 24x7 SOC',
      description: 'Real-time telemetry ingestion across payment switches, ATMs, NetBanking, and branch endpoints with sub-minute alert dispatch.',
      status: rbiControlOverrides['RBI-CSF-05'] || 'COMPLIANT',
      evidence: 'Continuous CyberGuard Grid SOC Telemetry Engine active with WebSocket streaming.',
      remediationAction: 'Review SOC SLA for critical alerts to maintain under 5 minutes.'
    },
    {
      id: 'RBI-CSF-06',
      category: 'Payment Switch Security',
      name: 'NPCI & UPI 2.0 Real-Time Velocity Throttling & Fraud Detection',
      mandate: 'NPCI Procedural Guidelines & RBI Cyber Security Guidelines for Payments',
      description: 'High-frequency transaction probing and micro-debit velocity anomalies must trigger automatic throttling.',
      status: rbiControlOverrides['RBI-CSF-06'] || (paymentCompromised ? 'NON_COMPLIANT' : 'COMPLIANT'),
      evidence: paymentCompromised ? 'High-velocity burst active (>400 debits/min); manual containment pending.' : 'UPI AI Sentry active; velocity thresholds set to 12 debits/min.',
      remediationAction: 'Execute containment playbook to throttle suspect merchant VPAs.'
    },
    {
      id: 'RBI-CSF-07',
      category: 'Web Application Security & Anti-Phishing',
      name: 'WAF Rate Limiting & Rogue Domain / Anti-Phishing Telemetry',
      mandate: 'RBI CSITE Circular 2022/104 - Anti-Phishing Directives',
      description: 'Internet Banking reverse proxy must enforce adaptive rate-limiting, CAPTCHA on failed login bursts, and active takedown feeds.',
      status: rbiControlOverrides['RBI-CSF-07'] || (netbankAtRisk ? 'PARTIAL' : 'COMPLIANT'),
      evidence: netbankAtRisk ? 'Credential stuffing burst flagged; step-up challenges active on affected CIDRs.' : 'WAF reverse proxy active with automated IP reputation filtering.',
      remediationAction: 'Enforce Step-Up OTP challenge across all NetBanking login endpoints.'
    },
    {
      id: 'RBI-CSF-08',
      category: 'Disaster Recovery & Business Continuity',
      name: 'Immutable WORM Storage for Off-Site Disaster Recovery Backups',
      mandate: 'RBI Master Directions Section 9 - Business Continuity & DR',
      description: 'Synchronous data replication to off-site location (Hyderabad) with Write-Once-Read-Many (WORM) ransomware protection.',
      status: rbiControlOverrides['RBI-CSF-08'] || 'COMPLIANT',
      evidence: 'Hyderabad DR site synchronized with 0.8s lag; NetApp SnapLock WORM active.',
      remediationAction: 'Conduct semi-annual automated DR failover drill.'
    },
    {
      id: 'RBI-CSF-09',
      category: 'Database Activity Monitoring (DAM)',
      name: 'Real-Time Database Activity Monitoring & Off-Hours Query Alarms',
      mandate: 'RBI CSITE Circular 2020 - Core Banking Database Auditing',
      description: 'Bulk query exports outside normal business clearing windows must trigger instant supervisory alerts.',
      status: rbiControlOverrides['RBI-CSF-09'] || 'COMPLIANT',
      evidence: 'DAM agent deployed on Oracle RAC; 10,000+ record thresholds configured.',
      remediationAction: 'Verify authorized change windows with Head of Core Operations.'
    },
    {
      id: 'RBI-CSF-10',
      category: 'Endpoint Security & Peripheral Lockdown',
      name: 'Removable Media (USB) Port Lockdown & Behavioral EDR on Teller PCs',
      mandate: 'RBI Cyber Security Framework Annex-2 (Endpoint Hardening)',
      description: 'All branch teller workstations must have mass storage ports disabled by GPO and run behavioral canary tripwires.',
      status: rbiControlOverrides['RBI-CSF-10'] || 'COMPLIANT',
      evidence: 'Group Policy enforces USB storage blocking; behavioral EDR agent deployed.',
      remediationAction: 'Audit branch endpoint agent heartbeat across regional branches.'
    },
    {
      id: 'RBI-CSF-11',
      category: 'Board Governance & CISO Oversight',
      name: 'Board Information Security Committee (ITSC) & CISO Quarterly Reporting',
      mandate: 'RBI Master Directions Section 2.1 - Governance Structure',
      description: 'Regular quantification of cyber risk, threat intelligence metrics, and audit hash-chain logs presented to Board of Directors.',
      status: rbiControlOverrides['RBI-CSF-11'] || 'COMPLIANT',
      evidence: 'Executive CISO Briefing generator & Cryptographic DLT Trust Ledger active.',
      remediationAction: 'Schedule next quarterly cyber risk presentation for ITSC.'
    },
    {
      id: 'RBI-CSF-12',
      category: 'Statutory Incident Notification',
      name: 'Mandatory 6-Hour Incident Notification to CERT-In & RBI CSITE',
      mandate: 'CERT-In Directions 2022 & RBI Cyber Incident Reporting Guidelines',
      description: 'All critical cybersecurity incidents must be formally reported to CERT-In and RBI within 6 hours of discovery.',
      status: rbiControlOverrides['RBI-CSF-12'] || 'COMPLIANT',
      evidence: 'Automated CERT-In Annexure 1 incident advisory exporter active.',
      remediationAction: 'Generate statutory report upon any critical severity incident triage.'
    }
  ];

  const compliantCount = baseControls.filter((c) => c.status === 'COMPLIANT').length;
  const partialCount = baseControls.filter((c) => c.status === 'PARTIAL').length;
  const nonCompliantCount = baseControls.filter((c) => c.status === 'NON_COMPLIANT').length;
  const scorePercentage = Math.round(((compliantCount + partialCount * 0.5) / baseControls.length) * 100);

  return res.json({
    institution: 'Demo Bank',
    regulatoryFramework: 'RBI Cyber Security Framework (CSITE) & Master Directions on IT Governance',
    complianceScore: scorePercentage,
    totalControls: baseControls.length,
    compliantCount,
    partialCount,
    nonCompliantCount,
    controls: baseControls,
    lastAuditTimestamp: new Date().toISOString()
  });
});

// POST /api/bank-assets/rbi-compliance/remediate - Remediate specific RBI Control Gap
bankAssetRouter.post('/rbi-compliance/remediate', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const orgId = user.orgId || 'org-1';
  const { controlId } = req.body;

  if (controlId) {
    rbiControlOverrides[controlId] = 'COMPLIANT';
    endpointDb.appendAudit(user.email, orgId, 'RBI_CONTROL_REMEDIATED', `Remediated control gap for ${controlId} to COMPLIANT.`);
  } else {
    rbiControlOverrides = {};
    endpointDb.appendAudit(user.email, orgId, 'RBI_ALL_CONTROLS_REMEDIATED', 'All RBI compliance gaps remediated to 100% baseline.');
  }

  return res.json({
    success: true,
    message: `Control ${controlId || 'ALL'} successfully remediated to COMPLIANT.`
  });
});

// GET /api/bank-assets/cert-in-report/:id - Mandated 6-Hour Incident Advisory Exporter
bankAssetRouter.get('/cert-in-report/:id', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const orgId = user.orgId || 'org-1';
  const event = endpointDb.getBankSecurityEventById(req.params.id) || endpointDb.getBankSecurityEvents(orgId, 1)[0];

  const reportId = `CERTIN-IN-2026-DEMOBANK-${req.params.id || 'EVT-001'}`;
  const now = new Date();

  const certInReport = {
    formTitle: 'ANNEXURE 1: CYBER INCIDENT REPORT TO CERT-IN & RBI CSITE',
    statutoryMandate: 'Reporting under Section 70B(6) of IT Act, 2000 & CERT-In Directions No. 20(3)/2022-CERT-In',
    mandatoryTimeline: 'Within 6 hours of incident identification',
    trackingNumber: reportId,
    generatedAtIST: now.toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }) + ' IST',
    reportingEntity: {
      organizationName: 'Demo Bank',
      institutionType: 'Scheduled Commercial Bank (BFSI)',
      country: 'India',
      headquarters: 'Connaught Place, New Delhi - 110001',
      cisoOfficeContact: 'ciso@demobank.com | +91-11-2345-6789'
    },
    incidentSummary: {
      incidentId: event?.id || 'evt-001',
      category: event?.event_category || 'Payment Fraud Anomaly',
      severity: event?.severity || 'CRITICAL',
      detectedAtIST: new Date(event?.timestamp || now.toISOString()).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }) + ' IST',
      affectedAsset: event?.affected_asset_name || 'UPI & Payment Gateway Processor (10.10.3.15)',
      description: event?.description || 'High-volume velocity micro-debit burst detected on UPI Gateway switch.',
      detectionSource: event?.detection_source || 'UPI AI Sentry & WAF Rate Limiter',
      investigationStatus: event?.investigation_status || 'INVESTIGATING'
    },
    technicalIoCs: {
      sourceIpRanges: ['198.51.100.42/28', '203.0.113.19 (Proxy Node)', '185.220.101.5 (Tor Exit)'],
      targetedProtocols: ['ISO 8583 Message Switch', 'NPCI UPI 2.0 API Gateway', 'HTTPS / WAF'],
      attackClassification: 'MITRE ATT&CK T1110 (Brute Force) & T1071.001 (Web Protocols)',
      compromiseEvidence: 'Velocity spike of 420 micro-debits/min originating from suspect merchant VPA handles.'
    },
    containmentAndMitigation: {
      immediateActionTaken: event?.recommended_action || 'Velocity throttling engaged on merchant endpoint; suspect VPAs frozen.',
      dataImpactAssessment: 'No core banking customer PII leaked. Finacle CBS enclave integrity verified intact.',
      forensicStatus: 'Memory snapshot captured; logs chained to immutable cryptographic DLT ledger.',
      containmentStatus: event?.investigation_status === 'RESOLVED' ? 'Neutralized and Remediated' : 'Active Containment & Throttling in Progress'
    },
    officerSignOff: {
      signatoryName: 'Bank SOC Administrator',
      designation: 'Lead Incident Commander, Cyber Defense Operations',
      authorizationStatus: 'OFFICIALLY STAMPED & DISPATCHED'
    }
  };

  return res.json({ report: certInReport });
});

// GET /api/bank-assets/fraud-rules - Banking Transaction Fraud Rules Telemetry
bankAssetRouter.get('/fraud-rules', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const orgId = user.orgId || 'org-1';
  const assets = endpointDb.getBankAssets(orgId);
  const paymentCompromised = assets.some((a) => a.id === 'asset-payment' && a.security_status === 'COMPROMISED');

  const fraudRules = [
    {
      id: 'RULE-TXN-01',
      name: 'UPI Micro-Debit Velocity Burst Sentry',
      description: 'Detects rapid burst of >10 micro-transactions (< ₹5.00) within 60 seconds targeting unverified merchant VPAs.',
      threshold: '>10 debits / minute',
      channel: 'UPI 2.0 / IMPS Gateway',
      status: paymentCompromised ? 'TRIGGERED' : 'MONITORING',
      evaluationsCount: 14250,
      triggeredCount: paymentCompromised ? 420 : 0,
      mitigationAction: 'Immediate velocity throttling and merchant settlement hold.'
    },
    {
      id: 'RULE-TXN-02',
      name: 'ATM Impossible Geolocation Travel Detector',
      description: 'Flags card authorization requests occurring across distant locations (>500 km) within an impossible physical transit window (< 45 mins).',
      threshold: '>500 km / 45 mins',
      channel: 'ATM Switch / NPCI NFS',
      status: 'MONITORING',
      evaluationsCount: 8940,
      triggeredCount: 2,
      mitigationAction: 'Trigger step-up OTP challenge and cardholder SMS alert.'
    },
    {
      id: 'RULE-TXN-03',
      name: 'High-Value Transfer Post-Credential Reset Tripwire',
      description: 'Detects high-value RTGS/NEFT transaction (> ₹2,00,000) initiated within 30 minutes of mobile MPIN or password change.',
      threshold: '> ₹2,00,000 within 30m of reset',
      channel: 'NetBanking / Mobile API',
      status: 'MONITORING',
      evaluationsCount: 3210,
      triggeredCount: 1,
      mitigationAction: 'Enforce 4-hour cooling window and branch verification.'
    }
  ];

  return res.json({ rules: fraudRules });
});

// POST /api/bank-assets/fraud-rules/simulate - Simulate Fraud Burst
bankAssetRouter.post('/fraud-rules/simulate', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const orgId = user.orgId || 'org-1';

  // Trigger UPI rule on asset-payment
  const asset = endpointDb.getBankAssetById('asset-payment');
  if (asset) {
    endpointDb.updateBankAsset(asset.id, {
      security_status: 'COMPROMISED',
      risk_score: Math.min(100, asset.risk_score + 35)
    });
  }

  const eventRecord: BankSecurityEventRecord = {
    id: `evt-fraud-${crypto.randomBytes(3).toString('hex')}`,
    org_id: orgId,
    affected_asset_id: 'asset-payment',
    event_category: 'UPI Micro-Debit Velocity Burst (RULE-TXN-01)',
    severity: 'CRITICAL',
    timestamp: new Date().toISOString(),
    description: 'Fraud Rule RULE-TXN-01 triggered: 420 micro-debits/min detected on UPI switch node.',
    detection_source: 'UPI AI Sentry',
    investigation_status: 'NEW',
    recommended_action: 'Apply instant velocity throttling and freeze payout destination VPA.'
  };
  endpointDb.saveBankSecurityEvent(eventRecord);
  endpointDb.appendAudit(user.email, orgId, 'FRAUD_RULE_TRIGGERED', 'Simulated RULE-TXN-01 UPI micro-debit velocity burst.');

  return res.json({
    success: true,
    ruleId: 'RULE-TXN-01',
    event: toBankSecurityEvent({ ...eventRecord, affected_asset_name: 'UPI & Payment Gateway Processor' })
  });
});


