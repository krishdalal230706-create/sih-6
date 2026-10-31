import { Router, Response } from 'express';
import crypto from 'crypto';
import { z } from 'zod';
import { endpointDb } from '../db/endpointDb.js';
import { requireAuth, requireAdmin, AuthenticatedRequest } from '../middleware/authMiddleware.js';
import { wsHub } from '../ws/wsHub.js';

export const deviceRouter = Router();

const enrollRequestSchema = z.object({
  enrollmentCode: z.string().min(5),
  hostname: z.string().min(1).max(100),
  os: z.string().min(1).max(100)
});

// List devices with real-time online status
deviceRouter.get('/', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  if (user.role === 'admin') {
    const rawDevices = endpointDb.getDevicesByOrg(user.orgId);
    const devices = rawDevices.map((d) => ({
      ...d,
      isOnline: wsHub.isAgentOnline(d.id),
      status: wsHub.isAgentOnline(d.id) && d.status === 'Offline' ? 'Healthy' : d.status
    }));
    return res.json({ devices });
  } else {
    const device = endpointDb.getDeviceByUserId(user.userId);
    const devices = device
      ? [{ ...device, isOnline: wsHub.isAgentOnline(device.id) }]
      : [];
    return res.json({ devices });
  }
});

// Generate an enrollment code (Admin only, scoped to org)
deviceRouter.post('/enrollment-code', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const targetUserId = req.body.userId || user.userId;
  const targetUser = endpointDb.getUserById(targetUserId);

  if (!targetUser || targetUser.org_id !== user.orgId) {
    return res.status(400).json({ error: 'INVALID_USER', message: 'Target user does not belong to your organization.' });
  }

  const code = endpointDb.createEnrollmentCode(user.orgId, targetUserId, 120); // 2 hours TTL
  endpointDb.appendAudit(user.email, user.orgId, 'ENROLLMENT_CODE_CREATED', `Admin generated enrollment code for user ${targetUser.email}`);

  return res.json({
    success: true,
    enrollmentCode: code,
    expiresInMinutes: 120,
    orgId: user.orgId,
    assignedUser: targetUser.email
  });
});

// Device Enrollment Handshake (public endpoint called by new agent CLI)
deviceRouter.post('/enroll', (req, res: Response) => {
  const parseResult = enrollRequestSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({ error: 'INVALID_ENROLLMENT_DATA', details: parseResult.error.issues.map((i) => i.message) });
  }

  const { enrollmentCode, hostname, os } = parseResult.data;
  const enrollment = endpointDb.consumeEnrollmentCode(enrollmentCode);

  if (!enrollment) {
    return res.status(403).json({ error: 'INVALID_OR_EXPIRED_CODE', message: 'Enrollment code is invalid, expired, or already used.' });
  }

  const now = new Date().toISOString();
  const deviceId = `DEV-${enrollment.org_id.toUpperCase().replace('-', '')}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;
  const token = `token-${crypto.randomBytes(16).toString('hex')}`;
  const commandSecret = `cmdsec-${crypto.randomBytes(20).toString('hex')}`;

  const device = {
    id: deviceId,
    org_id: enrollment.org_id,
    user_id: enrollment.user_id,
    hostname,
    os,
    status: 'Healthy' as const,
    risk: 15,
    last_seen: now,
    enrolled_at: now
  };

  endpointDb.registerDevice(device, commandSecret, token);
  endpointDb.appendAudit('agent-installer', enrollment.org_id, 'DEVICE_ENROLLED', `New endpoint device ${deviceId} (${hostname}, ${os}) enrolled successfully.`, deviceId);

  // Notify admins
  wsHub.broadcastToAdmins(enrollment.org_id, {
    type: 'DEVICE_ENROLLED',
    device,
    timestamp: now
  });

  return res.json({
    success: true,
    deviceId,
    orgId: enrollment.org_id,
    token,
    commandSecret,
    message: `Enrollment successful. Workstation registered to ${enrollment.org_id}.`
  });
});

// My Device endpoint (for regular users & agent status checks)
deviceRouter.get('/my-device', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const device = endpointDb.getDeviceByUserId(user.userId);
  if (!device) {
    return res.status(404).json({
      error: 'NO_DEVICE_ENROLLED',
      message: 'No endpoint device enrolled for your user account.'
    });
  }

  const recentEvents = endpointDb.getRecentDeviceEvents(device.id, 20);
  const commands = endpointDb.getCommandsForDevice(device.id);

  // Return device with notifications and notices for the user
  const recentNotices = commands
    .filter((c) => c.status === 'Executed' || c.status === 'Sent' || c.status === 'Pending')
    .slice(0, 5)
    .map((c) => ({
      commandId: c.id,
      action: c.action,
      status: c.status,
      issuedAt: c.issued_at,
      message: `Admin issued remediation action "${c.action}" on your workstation.`
    }));

  return res.json({
    device,
    recentEvents,
    recentNotices,
    mustResetPassword: user.mustReset
  });
});

// Single Device Details
deviceRouter.get('/:id', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const device = endpointDb.getDeviceById(req.params.id);

  if (!device) {
    return res.status(404).json({ error: 'DEVICE_NOT_FOUND', message: 'Device not found.' });
  }

  // Cross-org check for admins
  if (user.role === 'admin' && device.org_id !== user.orgId) {
    return res.status(403).json({ error: 'FORBIDDEN_ORG', message: 'Device belongs to another organization.' });
  }

  // Ownership check for regular users
  if (user.role === 'user' && device.user_id !== user.userId) {
    return res.status(403).json({ error: 'FORBIDDEN_DEVICE', message: 'You are only authorized to view your own device.' });
  }

  const recentEvents = endpointDb.getRecentDeviceEvents(device.id, 50);
  const commands = endpointDb.getCommandsForDevice(device.id);

  return res.json({
    device,
    recentEvents,
    commands
  });
});

// Device Detection & Explainability Waterfall Endpoint
deviceRouter.get('/:id/detection', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = req.user!;
  const device = endpointDb.getDeviceById(req.params.id);

  if (!device) {
    return res.status(404).json({ error: 'DEVICE_NOT_FOUND', message: 'Device not found.' });
  }

  if (user.role === 'admin' && device.org_id !== user.orgId) {
    return res.status(403).json({ error: 'FORBIDDEN_ORG', message: 'Device belongs to another organization.' });
  }

  const { endpointDetectionEngine } = require('../engine/endpointDetectionEngine.js');
  const detection = endpointDetectionEngine.getLatestDetection(device.id);

  if (detection) {
    return res.json({ detection });
  }

  // If no active alert triggered yet, return baseline posture factors
  const baselineFactors = [
    {
      id: 'fc-base-1',
      category: 'Authentication',
      points: 10,
      explanation: 'Interactive password logon active; FIDO2 hardware token not enforced.',
      severity: 'LOW'
    },
    {
      id: 'fc-base-2',
      category: 'Endpoint Security',
      points: 5,
      explanation: 'Workstation OS security baseline intact and monitoring active.',
      severity: 'LOW'
    }
  ];

  return res.json({
    detection: {
      detected: false,
      deviceId: device.id,
      orgId: device.org_id,
      hostname: device.hostname,
      userEmail: device.user_email,
      status: device.status,
      confidence: 95,
      severity: 'LOW',
      title: `NORMAL TELEMETRY BASELINE ON ${device.hostname}`,
      summary: 'No active threat rules breached in sliding window.',
      matchedRules: [],
      factorContributions: baselineFactors,
      incidentId: null,
      timestamp: new Date().toISOString()
    }
  });
});

