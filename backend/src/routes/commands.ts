import { Router, Response } from 'express';
import crypto from 'crypto';
import path from 'path';
import { z } from 'zod';
import { endpointDb, CommandRecord } from '../db/endpointDb.js';
import { requireAuth, requireAdmin, AuthenticatedRequest } from '../middleware/authMiddleware.js';
import { wsHub } from '../ws/wsHub.js';

export const commandRouter = Router();

export function computeCommandSignature(
  secret: string,
  commandId: string,
  deviceId: string,
  action: string,
  params: Record<string, any>,
  issuedBy: string,
  issuedAt: string,
  expiresAt: string,
  nonce: string
): string {
  const sortedParams = JSON.stringify(params, Object.keys(params).sort());
  const payload = `${commandId}|${deviceId}|${action}|${sortedParams}|${issuedBy}|${issuedAt}|${expiresAt}|${nonce}`;
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

const issueCommandSchema = z.object({
  deviceId: z.string().min(1),
  action: z.enum([
    'kill_process',
    'force_logout',
    'isolate_device',
    'release_isolation',
    'quarantine_file',
    'reset_credentials',
    'collect_diagnostics'
  ]),
  params: z.record(z.string(), z.any()).default({})
});

// Admin issues a remote remediation command
commandRouter.post('/issue', requireAuth, requireAdmin, async (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const parseResult = issueCommandSchema.safeParse(req.body);

  if (!parseResult.success) {
    endpointDb.appendAudit(
      user.email,
      user.orgId,
      'COMMAND_REJECTED_SCHEMA',
      `Command issuance rejected: Invalid request schema. ${JSON.stringify(parseResult.error.issues.map((i) => i.message))}`
    );
    return res.status(400).json({
      error: 'INVALID_COMMAND_SCHEMA',
      details: parseResult.error.issues.map((i) => i.message)
    });
  }

  const { deviceId, action, params } = parseResult.data;
  const device = endpointDb.getDeviceById(deviceId);

  if (!device) {
    return res.status(404).json({ error: 'DEVICE_NOT_FOUND', message: 'Target device not found.' });
  }

  // Cross-tenant organization isolation check
  if (device.org_id !== user.orgId) {
    endpointDb.appendAudit(
      user.email,
      user.orgId,
      'CROSS_ORG_ACCESS_BLOCKED',
      `Admin attempted cross-organization command "${action}" on device ${deviceId} belonging to ${device.org_id}.`,
      deviceId
    );
    return res.status(403).json({
      error: 'FORBIDDEN_ORG',
      message: `Access denied: Target device belongs to a different organization (${device.org_id}). Cross-tenant command execution is strictly forbidden.`
    });
  }

  // Parameter validations for safety whitelist
  if (action === 'kill_process') {
    const processName = params.processName || 'demo_suspicious';
    if (processName !== 'demo_suspicious') {
      endpointDb.appendAudit(
        user.email,
        user.orgId,
        'COMMAND_REJECTED_WHITELIST',
        `kill_process rejected: Attempted to target arbitrary process "${processName}". Only tracked "demo_suspicious" is permitted.`,
        deviceId
      );
      return res.status(400).json({
        error: 'ARBITRARY_PROCESS_KILL_BLOCKED',
        message: 'Security Whitelist: kill_process is restricted strictly to the tracked harmless test process "demo_suspicious". Arbitrary PIDs/executables are blocked.'
      });
    }
    params.processName = 'demo_suspicious';
  } else if (action === 'quarantine_file') {
    const filename = params.filename;
    if (!filename || typeof filename !== 'string') {
      return res.status(400).json({
        error: 'MISSING_FILENAME',
        message: 'quarantine_file requires a valid filename parameter.'
      });
    }

    const normalized = path.normalize(filename);
    if (normalized.includes('..') || path.isAbsolute(normalized)) {
      endpointDb.appendAudit(
        user.email,
        user.orgId,
        'PATH_TRAVERSAL_ATTEMPT_BLOCKED',
        `quarantine_file rejected: Path traversal sequence detected in filename "${filename}".`,
        deviceId
      );
      return res.status(400).json({
        error: 'PATH_TRAVERSAL_BLOCKED',
        message: 'Security sandbox violation: Path traversal characters ("..", absolute paths) are strictly prohibited. Files must reside inside agent/sandbox/.'
      });
    }
  }

  // Fetch command signing secret for this device
  const secretRecord = endpointDb.getDeviceSecret(deviceId);
  if (!secretRecord || !secretRecord.command_secret) {
    return res.status(500).json({
      error: 'COMMAND_SECRET_UNAVAILABLE',
      message: 'Per-device command signing secret could not be retrieved.'
    });
  }

  const now = new Date();
  const commandId = `cmd-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
  const nonce = `n-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  const issuedAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + 60 * 1000).toISOString(); // 60s short TTL

  // Compute HMAC-SHA256 signature
  const signature = computeCommandSignature(
    secretRecord.command_secret,
    commandId,
    deviceId,
    action,
    params,
    user.email,
    issuedAt,
    expiresAt,
    nonce
  );

  const commandRecord: CommandRecord = {
    id: commandId,
    device_id: deviceId,
    action,
    params: JSON.stringify(params),
    status: 'Pending',
    issued_by: user.email,
    issued_at: issuedAt,
    expires_at: expiresAt,
    nonce,
    signature,
    result: null,
    result_at: null
  };

  endpointDb.recordCommand(commandRecord);
  endpointDb.appendAudit(
    user.email,
    user.orgId,
    'COMMAND_ISSUED',
    `Admin issued remediation command "${action}" to ${deviceId} (Command ID: ${commandId}, Nonce: ${nonce}).`,
    deviceId
  );

  const isOnline = wsHub.isAgentOnline(deviceId);

  if (isOnline) {
    const sent = wsHub.sendToAgent(deviceId, {
      type: 'COMMAND',
      command: {
        id: commandId,
        deviceId,
        action,
        params,
        issuedBy: user.email,
        issuedAt,
        expiresAt,
        nonce,
        signature
      }
    });

    if (sent) {
      endpointDb.updateCommandStatus(commandId, 'Sent');
      commandRecord.status = 'Sent';
    }
  }

  return res.json({
    success: true,
    command: commandRecord,
    isOnline,
    status: commandRecord.status,
    message: isOnline
      ? `Remediation command "${action}" signed and transmitted to online agent.`
      : `Endpoint ${deviceId} is currently offline. Command queued in tamper-evident database with 60s TTL.`
  });
});

// List commands for a device
commandRouter.get('/device/:deviceId', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const device = endpointDb.getDeviceById(req.params.deviceId);

  if (!device) {
    return res.status(404).json({ error: 'DEVICE_NOT_FOUND', message: 'Device not found' });
  }

  if (user.role === 'admin' && device.org_id !== user.orgId) {
    return res.status(403).json({ error: 'FORBIDDEN_ORG', message: 'Device belongs to another organization' });
  }

  if (user.role === 'user' && device.user_id !== user.userId) {
    return res.status(403).json({ error: 'FORBIDDEN_DEVICE', message: 'Not authorized to view other devices' });
  }

  const commands = endpointDb.getCommandsForDevice(device.id);
  return res.json({ commands });
});
