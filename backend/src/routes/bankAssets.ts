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
