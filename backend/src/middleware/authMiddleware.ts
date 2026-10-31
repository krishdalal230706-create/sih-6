import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { AUTH_CONFIG } from '../config/authConfig.js';
import { endpointDb, UserRecord } from '../db/endpointDb.js';

export interface AuthUserPayload {
  userId: string;
  email: string;
  name: string;
  role: 'admin' | 'user';
  orgId: string;
  status: 'active' | 'locked' | 'reset_required' | 'pending';
  mfaRequired: boolean;
  privilegeLevel: 'STANDARD' | 'ELEVATED' | 'ADMIN';
  mustReset?: boolean;
}

export interface AuthenticatedRequest extends Request {
  user?: AuthUserPayload;
  rawToken?: string;
}

export function signUserToken(user: UserRecord): string {
  const payload: AuthUserPayload = {
    userId: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    orgId: user.org_id,
    status: user.status || 'active',
    mfaRequired: user.mfa_required === 1,
    privilegeLevel: user.privilege_level || (user.role === 'admin' ? 'ADMIN' : 'STANDARD'),
    mustReset: user.must_reset === 1 || user.status === 'reset_required'
  };
  return jwt.sign(payload, AUTH_CONFIG.JWT_SECRET, { expiresIn: '24h', jwtid: crypto.randomUUID() });
}

export function verifyUserToken(token: string): AuthUserPayload | null {
  try {
    return jwt.verify(token, AUTH_CONFIG.JWT_SECRET) as AuthUserPayload;
  } catch {
    return null;
  }
}

export function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'UNAUTHORIZED', message: 'Authentication required. Missing Bearer token.' });
  }

  const token = authHeader.split(' ')[1];
  const payload = verifyUserToken(token);
  if (!payload) {
    return res.status(401).json({ error: 'TOKEN_INVALID_OR_EXPIRED', message: 'Invalid or expired token.' });
  }

  // Check latest user status directly from database to reflect real-time locks/resets
  const user = endpointDb.getUserById(payload.userId);
  if (!user) {
    return res.status(401).json({ error: 'USER_NOT_FOUND', message: 'User record no longer exists.' });
  }

  // Check if user is locked
  if (user.status === 'locked') {
    return res.status(403).json({
      error: 'ACCOUNT_LOCKED',
      message: 'Your account was locked by an administrator for security reasons. Please contact your SOC administrator.'
    });
  }

  // Check if user is pending approval
  if (user.status === 'pending') {
    return res.status(403).json({
      error: 'ACCOUNT_PENDING_APPROVAL',
      message: 'Your account registration is awaiting approval from your organization administrator.'
    });
  }

  // Check if session has been revoked in database (e.g. via force_logout)
  if (!endpointDb.isSessionValid(token)) {
    return res.status(401).json({ error: 'SESSION_REVOKED', message: 'Session has been invalidated by administrator or user logout.' });
  }

  req.user = {
    userId: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    orgId: user.org_id,
    status: user.status || 'active',
    mfaRequired: user.mfa_required === 1,
    privilegeLevel: user.privilege_level || (user.role === 'admin' ? 'ADMIN' : 'STANDARD'),
    mustReset: user.must_reset === 1 || user.status === 'reset_required'
  };
  req.rawToken = token;

  // If user must reset password and is not hitting reset endpoint, block access
  if (req.user && req.user.mustReset && !req.path.includes('/reset-password') && !req.path.includes('/me') && !req.path.includes('/logout')) {
    return res.status(403).json({
      error: 'PASSWORD_RESET_REQUIRED',
      message: 'You must set a new password before continuing.'
    });
  }

  next();
}

export function requireDemoMode(req: Request, res: Response, next: NextFunction) {
  if (process.env.DEMO_MODE !== 'true') {
    return res.status(403).json({
      error: 'DEMO_MODE_DISABLED',
      message: 'This simulation, tamper, or demo endpoint is only available when DEMO_MODE=true.'
    });
  }
  next();
}

export function requireAdmin(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'FORBIDDEN', message: 'Administrator privileges required for this action.' });
  }
  next();
}

export function requireSameOrg(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const targetOrgId = req.params.orgId || req.body.orgId || req.query.orgId;
  if (targetOrgId && req.user && req.user.role !== 'admin' && req.user.orgId !== targetOrgId) {
    return res.status(403).json({ error: 'FORBIDDEN_ORG', message: 'Access denied: cannot operate on a different organization.' });
  }
  next();
}

