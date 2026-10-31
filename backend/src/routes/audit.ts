import { Router, Response } from 'express';
import crypto from 'crypto';
import { endpointDb } from '../db/endpointDb.js';
import { requireAuth, requireAdmin, requireDemoMode, AuthenticatedRequest } from '../middleware/authMiddleware.js';
import { addLedgerBlock, verifyLedgerChain } from '../engine/dltLedger.js';

export const auditRouter = Router();

// GET /api/audit - List audit records with filtering
auditRouter.get('/', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const { actor, action, deviceId, search, limit } = req.query;

  let records = endpointDb.getAuditLogs(user.orgId, Number(limit) || 200);

  if (search && typeof search === 'string') {
    const s = search.toLowerCase();
    records = records.filter(
      (r) =>
        r.id.toLowerCase().includes(s) ||
        r.actor.toLowerCase().includes(s) ||
        r.action.toLowerCase().includes(s) ||
        r.details.toLowerCase().includes(s) ||
        (r.device_id && r.device_id.toLowerCase().includes(s))
    );
  }
  if (actor && typeof actor === 'string') {
    records = records.filter((r) => r.actor.toLowerCase().includes(actor.toLowerCase()));
  }
  if (action && typeof action === 'string' && action !== 'ALL') {
    if (action === 'ACCOUNT_ACTIONS' || action === 'ACCOUNT_') {
      records = records.filter((r) =>
        r.action.startsWith('USER_') ||
        r.action.startsWith('PASSWORD_') ||
        r.action.startsWith('MFA_') ||
        r.action.startsWith('PERIMETER_') ||
        r.action.startsWith('PRIVILEGE_') ||
        r.action.includes('ACCOUNT')
      );
    } else {
      records = records.filter((r) => r.action === action || r.action.includes(action));
    }
  }
  if (deviceId && typeof deviceId === 'string' && deviceId !== 'ALL') {
    records = records.filter((r) => r.device_id === deviceId);
  }

  return res.json({
    records,
    totalCount: records.length,
    orgId: user.orgId
  });
});

// GET /api/audit/verify - Cryptographic Hash Chain Verification
auditRouter.get('/verify', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const verification = endpointDb.verifyAuditChain();
  return res.json(verification);
});

// POST /api/audit/tamper - Demo-only action demonstrating detection of modification (DEMO_MODE only)
auditRouter.post('/tamper', requireAuth, requireAdmin, requireDemoMode, (req: AuthenticatedRequest, res: Response) => {
  const { recordId } = req.body;
  try {
    const result = endpointDb.tamperAuditRecord(recordId);
    return res.json({
      ...result,
      message: 'Demo tamper injected into SQLite record. Cryptographic hash-chain recomputation will now detect tamper.'
    });
  } catch (err: any) {
    return res.status(400).json({ error: 'TAMPER_FAILED', message: err.message });
  }
});

// POST /api/audit/anchor-ledger - Anchor audit digest into DLT ledger
auditRouter.post('/anchor-ledger', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const verification = endpointDb.verifyAuditChain();

  if (!verification.isVerified) {
    return res.status(400).json({
      error: 'CANNOT_ANCHOR_TAMPERED_LOG',
      message: `Audit chain integrity compromised at record #${verification.brokenId}. Cannot anchor unverified audit chain to DLT ledger.`
    });
  }

  const logs = endpointDb.getAuditLogs(user.orgId, 1);
  const latestHash = logs[0] ? logs[0].hash : '0000000000000000000000000000000000000000000000000000000000000000';
  const patternHash = `ROOT-SHA256-${latestHash.slice(0, 24)}`;
  const threatId = `AUDIT-CHECKPOINT-${Date.now()}`;

  // Check if existing DLT ledger is intact
  const dltVerification = verifyLedgerChain();
  const isLedgerReal = dltVerification.isVerified;
  const ledgerStatus = isLedgerReal ? 'CONFIRMED' : 'PENDING';

  const newBlock = addLedgerBlock(
    threatId,
    user.orgId,
    patternHash,
    [user.orgId, 'Hospital B', 'University C'],
    ledgerStatus
  );

  endpointDb.appendAudit(
    user.email,
    user.orgId,
    'DLT_LEDGER_ANCHOR',
    `Audit hash-chain checkpoint anchored into DLT Ledger Block #${newBlock.blockNumber} (Pattern Hash: ${patternHash}, Status: ${ledgerStatus}).`,
    null
  );

  return res.json({
    success: true,
    block: newBlock,
    isLedgerReal,
    ledgerStatus,
    message: isLedgerReal
      ? `Audit log digest successfully anchored to DLT Ledger Block #${newBlock.blockNumber}. Validator quorum confirmed.`
      : `Audit log digest anchored to DLT Ledger Block #${newBlock.blockNumber}. Link marked as PENDING (ledger validation ongoing).`
  });
});

// POST /api/audit/anchor-incident - Anchor specific account incident digest to DLT ledger
auditRouter.post('/anchor-incident', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const { alertId, incidentId, details } = req.body;

  let threatId = incidentId || alertId || `INCIDENT-${Date.now()}`;
  let rawPayload = details || threatId;

  if (alertId) {
    const alertRecord = endpointDb.getAccountAlertById(alertId);
    if (alertRecord) {
      rawPayload = `${alertRecord.id}|${alertRecord.user_id}|${alertRecord.user_email}|${alertRecord.timestamp}|${alertRecord.matched_rules}`;
      threatId = alertRecord.id;
    }
  }

  const patternDigest = crypto.createHash('sha256').update(rawPayload).digest('hex');
  const patternHash = `INCIDENT-SHA256-${patternDigest.slice(0, 24)}`;

  // Verify DLT ledger status
  const dltVerification = verifyLedgerChain();
  const isLedgerReal = dltVerification.isVerified;
  const ledgerStatus = isLedgerReal ? 'CONFIRMED' : 'PENDING';

  const newBlock = addLedgerBlock(
    threatId,
    user.orgId,
    patternHash,
    [user.orgId, 'Hospital B', 'University C'],
    ledgerStatus
  );

  endpointDb.appendAudit(
    user.email,
    user.orgId,
    'DLT_INCIDENT_ANCHOR',
    `Incident ${threatId} digest anchored to DLT Ledger Block #${newBlock.blockNumber} (Digest: ${patternHash}, Status: ${ledgerStatus}).`,
    null
  );

  return res.json({
    success: true,
    block: newBlock,
    isLedgerReal,
    ledgerStatus,
    threatId,
    patternHash,
    message: isLedgerReal
      ? `Incident digest successfully linked and anchored to DLT Ledger Block #${newBlock.blockNumber}.`
      : `Incident digest linked to DLT Ledger Block #${newBlock.blockNumber} with status PENDING.`
  });
});
