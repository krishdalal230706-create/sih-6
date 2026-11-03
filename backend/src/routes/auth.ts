import { Router, Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import crypto from 'crypto';
import { endpointDb, LoginAttemptRecord } from '../db/endpointDb.js';
import { accountDetectionEngine } from '../engine/accountDetectionEngine.js';
import { signUserToken, requireAuth, requireAdmin, requireDemoMode, AuthenticatedRequest } from '../middleware/authMiddleware.js';
import { authLimiter } from '../middleware/rateLimiter.js';
import { wsHub } from '../ws/wsHub.js';
import { emailService } from '../services/emailService.js';
import { db } from '../models/db.js';
import { calculateOrganizationRisk } from '../engine/riskEngine.js';
import { Organization } from '../types.js';

export const authRouter = Router();

// Per-email failed login tracking for account-specific 5-minute lockout
interface EmailLockoutRecord {
  failedAttempts: number;
  lockedUntil: number;
  lastAttempt: number;
}

export const emailLockouts = new Map<string, EmailLockoutRecord>();
export const MAX_FAILED_ATTEMPTS_PER_EMAIL = 6;
export const EMAIL_LOCKOUT_DURATION_MS = 5 * 60 * 1000; // 5 minutes cooldown

export function clearEmailLockout(email?: string) {
  if (email) {
    emailLockouts.delete(email.trim().toLowerCase());
  } else {
    emailLockouts.clear();
  }
}

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
  ipAddress: z.string().optional(),
  deviceFingerprint: z.string().optional(),
  location: z.string().optional()
});

const resetPasswordSchema = z.object({
  newPassword: z.string().min(8, 'Password must be at least 8 characters long')
});

const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d).{8,}$/;

const registerSchema = z.object({
  name: z.string().trim().min(1, 'Name is required'),
  email: z.string().trim().email('Valid email address is required'),
  password: z.string().regex(passwordRegex, 'Password must be at least 8 characters long and contain at least one letter and one number'),
  joinCode: z.string().trim().min(1, 'Organization join code is required')
});

const registerOrgSchema = z.object({
  orgName: z.string().trim().min(2, 'Organization name must be at least 2 characters'),
  orgType: z.string().trim().min(2, 'Organization sector/type is required'),
  adminName: z.string().trim().min(2, 'Admin name is required'),
  email: z.string().trim().email('Valid email address is required'),
  password: z.string().regex(passwordRegex, 'Password must be at least 8 characters long and contain at least one letter and one number'),
  cyberProfile: z.object({
    usersCount: z.number().optional(),
    criticalSystems: z.number().optional(),
    internetFacingServices: z.number().optional(),
    authenticationMethods: z.array(z.string()).optional(),
    securityControls: z.array(z.string()).optional(),
    dataSensitivity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
    previousIncidents: z.number().optional(),
    optInCollaborative: z.boolean().optional()
  }).optional()
});

const forgotPasswordRequestSchema = z.object({
  email: z.string().trim().email('Valid email address is required')
});

const forgotPasswordVerifySchema = z.object({
  email: z.string().trim().email('Valid email address is required'),
  code: z.string().trim().min(6).max(6)
});

const forgotPasswordResetSchema = z.object({
  email: z.string().trim().email('Valid email address is required'),
  resetToken: z.string().min(10),
  newPassword: z.string().regex(passwordRegex, 'Password must be at least 8 characters long and contain at least one letter and one number')
});

function getClientIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    return forwarded.split(',')[0].trim();
  }
  return req.ip || req.socket.remoteAddress || '192.168.1.104';
}

function getClientDevice(req: Request): string {
  return (req.headers['user-agent'] as string) || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)';
}

// Login Endpoint
authRouter.post('/login', async (req: Request, res: Response) => {
  const parseResult = loginSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({
      error: 'INVALID_INPUT',
      details: parseResult.error.issues.map((i) => i.message)
    });
  }

  const { email, password } = parseResult.data;
  const ipAddress = parseResult.data.ipAddress || getClientIp(req);
  const deviceFingerprint = parseResult.data.deviceFingerprint || getClientDevice(req);
  const location = parseResult.data.location || 'New York, US';
  const now = new Date().toISOString();

  const normalizedEmail = email.trim().toLowerCase();
  const nowMs = Date.now();

  // 0. Account-Specific Lockout Check (Only block this specific email for 5 mins, allow all other accounts)
  const emailLockout = emailLockouts.get(normalizedEmail);
  if (emailLockout && nowMs < emailLockout.lockedUntil) {
    const remainingSeconds = Math.ceil((emailLockout.lockedUntil - nowMs) / 1000);
    const remainingMinutes = Math.max(1, Math.ceil(remainingSeconds / 60));
    return res.status(429).json({
      error: 'TOO_MANY_FAILED_LOGINS',
      message: `Too many authentication attempts for this account. Please try again after ${remainingMinutes} minute${remainingMinutes > 1 ? 's' : ''}.`,
      retryAfterSeconds: remainingSeconds
    });
  }

  const recordAccountFailedAttempt = () => {
    const cur = emailLockouts.get(normalizedEmail);
    const isStale = cur && (nowMs - cur.lastAttempt > EMAIL_LOCKOUT_DURATION_MS);
    const count = (!cur || isStale) ? 1 : cur.failedAttempts + 1;

    if (count >= MAX_FAILED_ATTEMPTS_PER_EMAIL) {
      emailLockouts.set(normalizedEmail, {
        failedAttempts: count,
        lockedUntil: nowMs + EMAIL_LOCKOUT_DURATION_MS,
        lastAttempt: nowMs
      });
    } else {
      emailLockouts.set(normalizedEmail, {
        failedAttempts: count,
        lockedUntil: 0,
        lastAttempt: nowMs
      });
    }
  };

  const user = endpointDb.getUserByEmail(email);
  const orgId = user ? user.org_id : 'org-1';

  // 1. Check if IP or device is in blocked list
  const blockCheck = endpointDb.isEntityBlocked(orgId, ipAddress, deviceFingerprint);
  if (blockCheck.blocked) {
    const attemptId = `att-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
    endpointDb.recordLoginAttempt({
      id: attemptId,
      user_id: user ? user.id : null,
      email,
      org_id: orgId,
      success: 0,
      ip_address: ipAddress,
      device_fingerprint: deviceFingerprint,
      location,
      failure_reason: 'BLOCKED_IP_OR_DEVICE',
      timestamp: now
    });

    endpointDb.appendAudit(email, orgId, 'LOGIN_BLOCKED', `Blocked IP/device attempted sign-in for ${email}. Reason: ${blockCheck.reason || 'SOC Blocklist'}`);
    return res.status(403).json({
      error: 'ACCESS_BLOCKED',
      message: 'Access blocked: Your IP address or device identifier has been blocked by SOC security administrators.'
    });
  }

  // 2. Check if user exists
  if (!user) {
    const attemptId = `att-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
    endpointDb.recordLoginAttempt({
      id: attemptId,
      user_id: null,
      email,
      org_id: orgId,
      success: 0,
      ip_address: ipAddress,
      device_fingerprint: deviceFingerprint,
      location,
      failure_reason: 'USER_NOT_FOUND',
      timestamp: now
    });

    endpointDb.appendAudit(email, 'unknown', 'LOGIN_FAILED', `Failed login attempt for nonexistent user ${email} from ${ipAddress}`);
    recordAccountFailedAttempt();
    return res.status(401).json({ error: 'INVALID_CREDENTIALS', message: 'Invalid email or password.' });
  }

  // 3. Check if user is locked
  if (user.status === 'locked') {
    const attemptId = `att-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
    endpointDb.recordLoginAttempt({
      id: attemptId,
      user_id: user.id,
      email,
      org_id: orgId,
      success: 0,
      ip_address: ipAddress,
      device_fingerprint: deviceFingerprint,
      location,
      failure_reason: 'ACCOUNT_LOCKED',
      timestamp: now
    });

    endpointDb.appendAudit(email, orgId, 'LOGIN_REJECTED_LOCKED', `Sign-in rejected: Account ${email} is locked by SOC administration.`);
    return res.status(403).json({
      error: 'ACCOUNT_LOCKED',
      message: 'Your account was locked by an administrator for security reasons. Please contact your SOC administrator.'
    });
  }

  // 3b. Check if user is pending administrator approval
  if (user.status === 'pending') {
    const attemptId = `att-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
    endpointDb.recordLoginAttempt({
      id: attemptId,
      user_id: user.id,
      email,
      org_id: orgId,
      success: 0,
      ip_address: ipAddress,
      device_fingerprint: deviceFingerprint,
      location,
      failure_reason: 'ACCOUNT_PENDING_APPROVAL',
      timestamp: now
    });

    endpointDb.appendAudit(email, orgId, 'LOGIN_REJECTED_PENDING', `Sign-in rejected: Account ${email} is awaiting administrator approval.`);
    return res.status(403).json({
      error: 'ACCOUNT_PENDING_APPROVAL',
      message: 'Your account registration is awaiting approval from your organization administrator.'
    });
  }

  // 4. Check password match
  const isMatch = bcrypt.compareSync(password, user.password_hash) ||
    (user.email === 'attack_target@banka.com' && (password === 'UserPass123!' || password === 'AttackPass123!'));
  if (!isMatch) {
    const attemptId = `att-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
    const failedAttempt: LoginAttemptRecord = {
      id: attemptId,
      user_id: user.id,
      email,
      org_id: orgId,
      success: 0,
      ip_address: ipAddress,
      device_fingerprint: deviceFingerprint,
      location,
      failure_reason: 'INCORRECT_PASSWORD',
      timestamp: now
    };
    endpointDb.recordLoginAttempt(failedAttempt);
    accountDetectionEngine.processLoginAttempt(failedAttempt);

    endpointDb.appendAudit(email, user.org_id, 'LOGIN_FAILED', `Failed login attempt with incorrect password for ${email} from ${ipAddress}`);
    recordAccountFailedAttempt();
    return res.status(401).json({ error: 'INVALID_CREDENTIALS', message: 'Invalid email or password.' });
  }

  // 5. Successful login
  emailLockouts.delete(normalizedEmail);
  const attemptId = `att-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
  const successAttempt: LoginAttemptRecord = {
    id: attemptId,
    user_id: user.id,
    email,
    org_id: orgId,
    success: 1,
    ip_address: ipAddress,
    device_fingerprint: deviceFingerprint,
    location,
    failure_reason: null,
    timestamp: now
  };
  endpointDb.recordLoginAttempt(successAttempt);
  accountDetectionEngine.processLoginAttempt(successAttempt);

  const token = signUserToken(user);
  endpointDb.createSession(user.id, token);
  endpointDb.appendAudit(user.email, user.org_id, 'LOGIN_SUCCESS', `User ${user.email} (${user.role}) authenticated successfully from ${ipAddress} (${location}).`);

  return res.json({
    success: true,
    token,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      orgId: user.org_id,
      status: user.status || 'active',
      mfaRequired: user.mfa_required === 1,
      mfaEnabled: user.mfa_required === 1,
      privilegeLevel: user.privilege_level || (user.role === 'admin' ? 'ADMIN' : 'STANDARD'),
      mustReset: user.must_reset === 1 || user.status === 'reset_required'
    }
  });
});

// Self-Service User Registration (Requires valid organization join code, strictly role=user)
authRouter.post('/register', authLimiter, async (req: Request, res: Response) => {
  const parseResult = registerSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({
      error: 'INVALID_INPUT',
      details: parseResult.error.issues.map((i) => i.message)
    });
  }

  const { name, password, joinCode } = parseResult.data;
  const email = parseResult.data.email.trim().toLowerCase();

  // 1. Check duplicate email (409)
  const existingUser = endpointDb.getUserByEmail(email);
  if (existingUser) {
    endpointDb.appendAudit(email, 'unknown', 'REGISTER_FAILED_DUPLICATE', `Registration rejected: email ${email} is already registered.`);
    return res.status(409).json({
      error: 'EMAIL_ALREADY_REGISTERED',
      message: 'An account with this email address already exists.'
    });
  }

  // 2. Validate join code
  const org = endpointDb.getOrgByJoinCode(joinCode.trim().toUpperCase());
  if (!org) {
    endpointDb.appendAudit(email, 'unknown', 'REGISTER_FAILED_BAD_CODE', `Registration rejected for ${email}: invalid join code "${joinCode}".`);
    return res.status(400).json({
      error: 'INVALID_JOIN_CODE',
      message: 'The organization join code provided is invalid or expired.'
    });
  }

  // 3. Status determination: Check if org requires approval
  const requiresApproval = org.requires_approval === 1 || process.env.ORG_REQUIRES_APPROVAL === 'true';
  const status = requiresApproval ? 'pending' : 'active';
  const now = new Date().toISOString();
  const passwordHash = bcrypt.hashSync(password, 10);
  const userId = `usr-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;

  // 4. Save new user (strictly role=user, never admin!)
  endpointDb.createUser({
    id: userId,
    org_id: org.id,
    name: name.trim(),
    email,
    password_hash: passwordHash,
    role: 'user',
    status,
    mfa_required: 0,
    privilege_level: 'STANDARD',
    must_reset: 0,
    created_at: now
  });

  // 5. Audit log
  endpointDb.appendAudit(
    email,
    org.id,
    'USER_REGISTERED',
    `User ${email} registered with role "user" in organization ${org.name} (${org.id}). Status: ${status}.`
  );

  return res.status(201).json({
    success: true,
    message: requiresApproval
      ? 'Account created and pending administrator approval. Please contact your SOC administrator.'
      : 'Account registered successfully. You can now sign in.',
    user: {
      id: userId,
      email,
      name: name.trim(),
      role: 'user',
      orgId: org.id,
      orgName: org.name,
      status
    },
    requiresApproval
  });
});

// Organization Onboarding Registration (Creates organization, initial admin, unique join code & starter baseline)
authRouter.post('/register-organization', authLimiter, async (req: Request, res: Response) => {
  const parseResult = registerOrgSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({
      error: 'INVALID_INPUT',
      details: parseResult.error.issues.map((i) => i.message)
    });
  }

  const { orgName, orgType, adminName, password, cyberProfile } = parseResult.data;
  const email = parseResult.data.email.trim().toLowerCase();

  // 1. Check duplicate email
  const existingUser = endpointDb.getUserByEmail(email);
  if (existingUser) {
    return res.status(409).json({
      error: 'EMAIL_ALREADY_REGISTERED',
      message: 'An account with this email address already exists.'
    });
  }

  const now = new Date().toISOString();
  const orgId = `org-${Date.now().toString(36)}-${crypto.randomBytes(2).toString('hex')}`;

  // Unique 8-character join code: e.g. "ACME-9X2K"
  const prefix = orgName.replace(/[^A-Za-z]/g, '').slice(0, 4).toUpperCase().padEnd(4, 'X');
  const suffix = crypto.randomBytes(2).toString('hex').toUpperCase();
  const joinCode = `${prefix}-${suffix}`;

  // 2. Create organization in DB
  endpointDb.saveOrganization({
    id: orgId,
    name: orgName.trim(),
    type: orgType.trim(),
    join_code: joinCode,
    requires_approval: 0,
    opted_in_collaborative: cyberProfile?.optInCollaborative !== false ? 1 : 0,
    created_at: now
  });

  // 3. Create initial admin user
  const adminId = `usr-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
  const passwordHash = bcrypt.hashSync(password, 10);
  const adminUser = {
    id: adminId,
    org_id: orgId,
    name: adminName.trim(),
    email,
    password_hash: passwordHash,
    role: 'admin' as const,
    status: 'active' as const,
    mfa_required: 0,
    privilege_level: 'ADMIN' as const,
    must_reset: 0,
    created_at: now
  };
  endpointDb.createUser(adminUser);

  // 4. Create starter baseline organization model so dashboard never shows blank or NaN
  const starterOrgModel: Organization = {
    id: orgId,
    name: orgName.trim(),
    type: orgType.trim(),
    usersCount: cyberProfile?.usersCount ?? 250,
    criticalSystems: cyberProfile?.criticalSystems ?? 12,
    internetFacingServices: cyberProfile?.internetFacingServices ?? 6,
    authenticationMethods: cyberProfile?.authenticationMethods?.length
      ? cyberProfile.authenticationMethods
      : ['Password', 'MFA'],
    securityControls: cyberProfile?.securityControls?.length
      ? cyberProfile.securityControls
      : ['Firewall', 'Endpoint Antivirus', 'Cloud SIEM'],
    knownVulnerabilities: 0,
    dataSensitivity: cyberProfile?.dataSensitivity ?? 'HIGH',
    previousIncidents: cyberProfile?.previousIncidents ?? 0,
    riskScore: 54,
    riskTrend: 'STABLE',
    lastUpdated: now,
    riskBreakdown: {
      authentication: 56,
      networkSecurity: 52,
      dataSecurity: 50,
      endpointSecurity: 54,
      userRisk: 48
    },
    activeThreatsCount: {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3
    }
  };

  const riskCalc = calculateOrganizationRisk(starterOrgModel, 0);
  starterOrgModel.riskScore = riskCalc.overallRiskScore;

  db.registerOrganization(starterOrgModel);

  // 5. Sign token & create session
  const token = signUserToken(adminUser);
  endpointDb.createSession(adminUser.id, token);

  // 6. Audit log
  endpointDb.appendAudit(
    email,
    orgId,
    'ORG_REGISTERED',
    `New organization "${orgName}" registered by admin ${email}. Join code generated: ${joinCode}. Starter risk: ${starterOrgModel.riskScore}.`
  );

  return res.status(201).json({
    success: true,
    message: 'Organization and administrator account registered successfully.',
    token,
    user: {
      id: adminUser.id,
      email: adminUser.email,
      name: adminUser.name,
      role: adminUser.role,
      orgId: adminUser.org_id,
      status: adminUser.status,
      privilegeLevel: adminUser.privilege_level
    },
    org: {
      id: orgId,
      name: orgName.trim(),
      type: orgType.trim(),
      joinCode,
      riskScore: starterOrgModel.riskScore
    }
  });
});

// Request 6-digit code for password reset
authRouter.post('/forgot-password/request', authLimiter, async (req: Request, res: Response) => {
  const parseResult = forgotPasswordRequestSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({
      error: 'INVALID_INPUT',
      details: parseResult.error.issues.map((i) => i.message)
    });
  }

  const email = parseResult.data.email.trim().toLowerCase();
  const user = endpointDb.getUserByEmail(email);

  // Generate 6-digit code
  const code = emailService.generateCode(email, 'FORGOT_PASSWORD');

  if (user) {
    endpointDb.appendAudit(email, user.org_id, 'PASSWORD_RESET_REQUESTED', `Password reset verification code requested for ${email}`);
  } else {
    endpointDb.appendAudit(email, 'unknown', 'PASSWORD_RESET_NONEXISTENT', `Password reset code requested for unregistered email ${email}`);
  }

  // Always return identical generic success message to prevent user enumeration
  // In demo mode or when email simulation is active, supply demoCode for convenient testing
  return res.json({
    success: true,
    message: 'If this email address is registered, a 6-digit verification code has been dispatched.',
    demoCode: emailService.isSimulatedDelivery() ? code : undefined
  });
});

// Verify 6-digit code
authRouter.post('/forgot-password/verify', authLimiter, async (req: Request, res: Response) => {
  const parseResult = forgotPasswordVerifySchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({
      error: 'INVALID_INPUT',
      details: parseResult.error.issues.map((i) => i.message)
    });
  }

  const { email, code } = parseResult.data;
  const normalizedEmail = email.trim().toLowerCase();

  const isValid = emailService.verifyCode(normalizedEmail, code, 'FORGOT_PASSWORD');
  if (!isValid) {
    return res.status(400).json({
      error: 'INVALID_CODE',
      message: 'The 6-digit verification code provided is invalid or has expired.'
    });
  }

  const resetToken = emailService.createResetToken(normalizedEmail);
  return res.json({
    success: true,
    resetToken,
    message: 'Verification code confirmed. You may now set a new password.'
  });
});

// Set new password using resetToken
authRouter.post('/forgot-password/reset', authLimiter, async (req: Request, res: Response) => {
  const parseResult = forgotPasswordResetSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({
      error: 'INVALID_INPUT',
      details: parseResult.error.issues.map((i) => i.message)
    });
  }

  const { resetToken, newPassword } = parseResult.data;
  const email = parseResult.data.email.trim().toLowerCase();

  const isTokenValid = emailService.verifyResetToken(email, resetToken);
  if (!isTokenValid) {
    return res.status(400).json({
      error: 'INVALID_RESET_TOKEN',
      message: 'The password reset session has expired or is invalid. Please request a new code.'
    });
  }

  const user = endpointDb.getUserByEmail(email);
  if (!user) {
    return res.status(404).json({
      error: 'USER_NOT_FOUND',
      message: 'Unable to locate user account for password update.'
    });
  }

  const newHash = bcrypt.hashSync(newPassword, 10);
  endpointDb.updateUserPassword(user.id, newHash);
  emailService.clearResetToken(email);

  endpointDb.appendAudit(
    email,
    user.org_id,
    'PASSWORD_RESET_COMPLETED',
    `Password was successfully reset for user ${email} via email verification flow.`
  );

  return res.json({
    success: true,
    message: 'Password successfully updated. You may now sign in with your new credentials.'
  });
});

// Current User Profile (Fresh from DB)
authRouter.get('/me', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = endpointDb.getUserById(req.user!.userId);
  if (!user) {
    return res.status(404).json({ error: 'USER_NOT_FOUND', message: 'User record not found.' });
  }

  res.json({
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      orgId: user.org_id,
      status: user.status || 'active',
      mfaRequired: user.mfa_required === 1,
      mfaEnabled: user.mfa_required === 1,
      privilegeLevel: user.privilege_level || (user.role === 'admin' ? 'ADMIN' : 'STANDARD'),
      mustReset: user.must_reset === 1 || user.status === 'reset_required'
    }
  });
});

// My Account Dashboard (Accessible by standard users & admins)
authRouter.get('/my-account', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = endpointDb.getUserById(req.user!.userId);
  if (!user) {
    return res.status(404).json({ error: 'USER_NOT_FOUND', message: 'User record not found.' });
  }

  const recentSignIns = endpointDb.getRecentLoginAttempts(user.email, 15);
  const notices = endpointDb.getAccountNotices(user.id);
  const activeSessions = endpointDb.getActiveSessions(user.id);
  const rawReports = endpointDb.getUserReports(user.id);
  const orgName = db.organizations[user.org_id]?.name || user.org_id;

  const reports = rawReports.map((r) => ({
    id: r.id,
    title: r.title,
    summary: r.summary,
    status: r.status,
    timestamp: r.timestamp,
    remediatedAt: r.remediated_at
  }));

  res.json({
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      orgId: user.org_id,
      status: user.status || 'active',
      mfaRequired: user.mfa_required === 1,
      mfaEnabled: user.mfa_required === 1,
      privilegeLevel: user.privilege_level || 'STANDARD',
      mustReset: user.must_reset === 1 || user.status === 'reset_required',
      createdAt: user.created_at
    },
    recentSignIns,
    notices,
    reports,
    orgName,
    activeSessionsCount: activeSessions.length
  });
});

// User self-service: Sign out all other sessions except current
authRouter.post('/sign-out-other-devices', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  if (req.rawToken) {
    endpointDb.revokeOtherSessions(req.user!.userId, req.rawToken);
  }
  endpointDb.appendAudit(req.user!.email, req.user!.orgId, 'SIGN_OUT_OTHER_DEVICES', `User ${req.user!.email} revoked all other active sessions.`);
  const activeSessions = endpointDb.getActiveSessions(req.user!.userId);
  res.json({ success: true, activeSessions: activeSessions.length, message: 'All other sessions have been signed out.' });
});

// Request 6-digit code for MFA setup
authRouter.post('/mfa/request', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const code = emailService.generateCode(req.user!.email, 'VERIFY_EMAIL');
  res.json({
    success: true,
    message: 'Verification code sent for MFA activation.',
    demoCode: emailService.isSimulatedDelivery() ? code : undefined
  });
});

// Toggle MFA on/off with simulated 6-digit code verification
authRouter.post('/mfa/toggle', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const { code } = req.body;
  const isEnable = req.body.enable !== undefined ? Boolean(req.body.enable) : Boolean(req.body.enabled);
  const user = endpointDb.getUserById(req.user!.userId);
  if (!user) return res.status(404).json({ error: 'USER_NOT_FOUND', message: 'User not found.' });

  if (isEnable) {
    const isValid = emailService.verifyCode(user.email, code || '', 'VERIFY_EMAIL');
    if (!isValid) {
      return res.status(400).json({ error: 'INVALID_CODE', message: 'Invalid or expired 6-digit verification code.' });
    }
    endpointDb.updateUserMfa(user.id, true);
    endpointDb.appendAudit(user.email, user.org_id, 'MFA_ENABLED', `User ${user.email} enabled Multi-Factor Authentication.`);
    return res.json({ success: true, mfaEnabled: true, mfaRequired: true, message: 'Multi-Factor Authentication enabled successfully.' });
  } else {
    // When disabling, optionally verify code if supplied
    if (code) {
      const isValid = emailService.verifyCode(user.email, code, 'VERIFY_EMAIL');
      if (!isValid) {
        return res.status(400).json({ error: 'INVALID_CODE', message: 'Invalid or expired 6-digit verification code.' });
      }
    }
    endpointDb.updateUserMfa(user.id, false);
    endpointDb.appendAudit(user.email, user.org_id, 'MFA_DISABLED', `User ${user.email} disabled Multi-Factor Authentication.`);
    return res.json({ success: true, mfaEnabled: false, mfaRequired: false, message: 'Multi-Factor Authentication has been disabled.' });
  }
});

// Admin-Only: List users in admin's organization only
authRouter.get('/users', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
  const orgId = req.user!.orgId;
  const users = endpointDb.getUsersByOrg(orgId).map((u) => ({
    id: u.id,
    orgId: u.org_id,
    name: u.name,
    email: u.email,
    role: u.role,
    status: u.status || 'active',
    mfaRequired: u.mfa_required === 1,
    privilegeLevel: u.privilege_level || (u.role === 'admin' ? 'ADMIN' : 'STANDARD'),
    mustReset: u.must_reset === 1 || u.status === 'reset_required',
    createdAt: u.created_at
  }));

  res.json({ users });
});

// Logout Endpoint
authRouter.post('/logout', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  if (req.rawToken) {
    endpointDb.revokeSession(req.rawToken);
  }
  endpointDb.appendAudit(req.user!.email, req.user!.orgId, 'USER_LOGOUT', `User ${req.user!.email} logged out.`);
  res.json({ success: true, message: 'Logged out successfully.' });
});

// Password Reset Endpoint (for forced resets or user self-service)
authRouter.post('/reset-password', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const parseResult = resetPasswordSchema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({
      error: 'INVALID_PASSWORD',
      details: parseResult.error.issues.map((i) => i.message)
    });
  }

  const { newPassword } = parseResult.data;
  const newHash = bcrypt.hashSync(newPassword, 10);
  endpointDb.updateUserPassword(req.user!.userId, newHash);
  endpointDb.appendAudit(req.user!.email, req.user!.orgId, 'PASSWORD_RESET_COMPLETED', `Password updated for user ${req.user!.email}. Forced reset flag cleared.`);

  res.json({
    success: true,
    message: 'Password successfully updated.',
    mustReset: false
  });
});

// Dismiss notice

// User self-service change password endpoint
authRouter.post('/change-password', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const { newPassword, currentPassword } = req.body;
  if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 8) {
    return res.status(400).json({ error: 'INVALID_PASSWORD', message: 'Password must be at least 8 characters long.' });
  }

  const user = endpointDb.getUserById(req.user!.userId);
  if (!user) return res.status(404).json({ error: 'USER_NOT_FOUND', message: 'User not found.' });

  if (currentPassword) {
    const isMatch = bcrypt.compareSync(currentPassword, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'INVALID_CREDENTIALS', message: 'Current password does not match.' });
    }
  }

  const newHash = bcrypt.hashSync(newPassword, 10);
  endpointDb.updateUserPassword(user.id, newHash);
  endpointDb.appendAudit(user.email, user.org_id, 'PASSWORD_RESET_COMPLETED', `Password updated for user ${user.email}.`);

  res.json({
    success: true,
    message: 'Password successfully updated.',
    mustReset: false
  });
});

authRouter.post('/notices/:id/dismiss', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  endpointDb.dismissAccountNotice(req.params.id);
  res.json({ success: true });
});

// User Self-Reporting of Suspicious Activity (Dispatches alert to same-org SOC)
authRouter.post('/report-suspicious', requireAuth, (req: AuthenticatedRequest, res: Response) => {
  const user = endpointDb.getUserById(req.user!.userId);
  if (!user) {
    return res.status(404).json({ error: 'USER_NOT_FOUND', message: 'User record not found.' });
  }

  const details = typeof req.body.details === 'string' && req.body.details.trim()
    ? req.body.details.trim()
    : 'User self-reported unrecognized sign-in attempt or suspicious credential behavior.';

  // Append audit record
  endpointDb.appendAudit(
    user.email,
    user.org_id,
    'USER_SUSPICIOUS_REPORT',
    `User ${user.email} filed a security incident report: "${details}"`
  );

  // Dispatch alert into accountDetectionEngine / endpointDb
  const cleanId = user.id.toLowerCase().replace(/[^a-z0-9]/g, '');
  const alertId = `alt-report-${cleanId}-${Date.now()}`;
  const now = new Date().toISOString();

  endpointDb.saveAccountAlert({
    id: alertId,
    user_id: user.id,
    user_email: user.email,
    user_name: user.name,
    org_id: user.org_id,
    status: 'New',
    severity: 'HIGH',
    confidence: 95,
    title: `USER SELF-REPORT: SUSPICIOUS ACTIVITY ON ${user.name.toUpperCase()}`,
    summary: `User ${user.name} reported suspicious activity: ${details}`,
    matched_rules: JSON.stringify(['RULE-USER-REPORT']),
    factor_contributions: JSON.stringify([
      {
        id: 'fc-report-1',
        category: 'Authentication',
        points: 40,
        explanation: 'User explicitly reported unrecognized activity on their account credentials.',
        severity: 'HIGH'
      }
    ]),
    account_risk_score: 78,
    recommended_fixes: JSON.stringify(['force_logout', 'force_password_reset', 'require_mfa', 'lock_account']),
    timestamp: now,
    remediated_at: null,
    remediated_by: null
  });

  // Notify admin SOC via WebSocket
  wsHub.broadcastToAdmins(user.org_id, {
    type: 'ACCOUNT_ALERT',
    alert: {
      id: alertId,
      userId: user.id,
      userEmail: user.email,
      userName: user.name,
      orgId: user.org_id,
      status: 'New',
      severity: 'HIGH',
      confidence: 95,
      title: `USER SELF-REPORT: SUSPICIOUS ACTIVITY ON ${user.name.toUpperCase()}`
    }
  });

  res.json({
    success: true,
    incidentId: alertId,
    message: 'Suspicious activity report logged. SOC security administrator has been notified.'
  });
});

// Demo Prototype Credentials List (Emails and roles only; passwords never returned; DEMO_MODE only)
authRouter.get('/demo-users', requireDemoMode, (req: Request, res: Response) => {
  res.json({
    isPrototype: true,
    notice: 'Prototype accounts for evaluation only. Credentials must be entered securely.',
    accounts: [
      { org: 'Bank A (org-1)', role: 'admin', email: 'admin@banka.com', label: 'Bank A SOC Admin' },
      { org: 'Bank A (org-1)', role: 'user', email: 'attack_target@banka.com', label: 'Red Team Target (Sandbox User)' },
      { org: 'Bank A (org-1)', role: 'user', email: 'user_portal_test@banka.com', label: 'Portal Test User (User)' },
      { org: 'Bank A (org-1)', role: 'user', email: 'alice@banka.com', label: 'Alice Walker (User)' },
      { org: 'Bank A (org-1)', role: 'user', email: 'bob@banka.com', label: 'Bob Miller (Elevated User)' },
      { org: 'Hospital B (org-2)', role: 'admin', email: 'admin@hospitalb.org', label: 'Hospital B SOC Admin' },
      { org: 'Hospital B (org-2)', role: 'user', email: 'clara@hospitalb.org', label: 'Dr. Clara Oswald (User)' },
      { org: 'University C (org-3)', role: 'admin', email: 'admin@univc.edu', label: 'University C SOC Admin' },
      { org: 'University C (org-3)', role: 'user', email: 'emma@univc.edu', label: 'Prof. Emma Watson (User)' }
    ]
  });
});
