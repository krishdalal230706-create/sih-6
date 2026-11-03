import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';

export interface OrganizationRecord {
  id: string;
  name: string;
  type: string;
  join_code: string;
  requires_approval: number;
  opted_in_collaborative: number;
  created_at: string;
}

export interface UserRecord {
  id: string;
  org_id: string;
  name: string;
  email: string;
  password_hash: string;
  role: 'admin' | 'user';
  status: 'active' | 'locked' | 'reset_required' | 'pending';
  mfa_required: number;
  privilege_level: 'STANDARD' | 'ELEVATED' | 'ADMIN';
  must_reset: number;
  created_at: string;
}

export interface LoginAttemptRecord {
  id: string;
  user_id: string | null;
  email: string;
  org_id: string;
  success: number;
  ip_address: string;
  device_fingerprint: string;
  location: string;
  failure_reason: string | null;
  timestamp: string;
}

export interface BlockedEntityRecord {
  id: string;
  org_id: string;
  entity_type: 'IP' | 'DEVICE';
  entity_value: string;
  blocked_by: string;
  blocked_at: string;
  reason: string;
}

export interface AccountNoticeRecord {
  id: string;
  user_id: string;
  org_id: string;
  notice_type: string;
  message: string;
  created_at: string;
  acknowledged: number;
}

export interface BankAssetRecord {
  id: string;
  org_id: string;
  name: string;
  category: string;
  description: string;
  criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  ip_or_identifier: string;
  technology_stack: string;
  owner_department: string;
  security_status: 'HEALTHY' | 'DEGRADED' | 'AT_RISK' | 'COMPROMISED' | 'MAINTENANCE';
  associated_vulns_count: number;
  last_assessment_date: string;
  risk_score: number;
  created_at: string;
  updated_at: string;
}

export interface BankSecurityEventRecord {
  id: string;
  org_id: string;
  affected_asset_id: string;
  event_category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  timestamp: string;
  description: string;
  detection_source: string;
  investigation_status: 'NEW' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED';
  recommended_action: string;
}

export interface AccountAlertRecord {
  id: string;
  user_id: string;
  user_email: string;
  user_name: string;
  org_id: string;
  status: 'New' | 'Investigating' | 'Remediated';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: number;
  title: string;
  summary: string;
  matched_rules: string;
  factor_contributions: string;
  account_risk_score: number;
  recommended_fixes: string;
  timestamp: string;
  remediated_at: string | null;
  remediated_by: string | null;
}

export interface DeviceRecord {
  id: string;
  org_id: string;
  user_id: string;
  hostname: string;
  os: string;
  status: 'Healthy' | 'Suspicious' | 'Compromised' | 'Isolated' | 'Remediated' | 'Offline';
  risk: number;
  last_seen: string;
  enrolled_at: string;
}

export interface DeviceSecretRecord {
  device_id: string;
  token_hash: string;
  command_secret: string;
}

export interface DeviceEventRecord {
  id: string;
  device_id: string;
  event_type: string;
  details: string;
  severity: string;
  timestamp: string;
}

export interface CommandRecord {
  id: string;
  device_id: string;
  action: string;
  params: string;
  status: 'Pending' | 'Sent' | 'Executed' | 'Failed' | 'Rejected';
  issued_by: string;
  issued_at: string;
  expires_at: string;
  nonce: string;
  signature: string;
  result: string | null;
  result_at: string | null;
}

export interface AuditRecord {
  id: string;
  ts: string;
  actor: string;
  org_id: string;
  device_id: string | null;
  action: string;
  details: string;
  prev_hash: string;
  hash: string;
}

export interface SessionRecord {
  id: string;
  user_id: string;
  token_hash: string;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
}

export interface EnrollmentCodeRecord {
  code: string;
  org_id: string;
  user_id: string;
  created_at: string;
  expires_at: string;
  used: number;
}

export function computeAuditHash(
  id: string,
  ts: string,
  actor: string,
  org_id: string,
  device_id: string | null,
  action: string,
  details: string,
  prev_hash: string
): string {
  const payload = `${id}|${ts}|${actor}|${org_id}|${device_id || ''}|${action}|${details}|${prev_hash}`;
  return crypto.createHash('sha256').update(payload).digest('hex');
}

export class EndpointDatabase {
  private db: Database.Database;
  private dbPath: string;
  private auditSeq = 0;

  constructor() {
    const backendDataDir = path.resolve(process.cwd(), 'backend', 'data');
    const localDataDir = path.resolve(process.cwd(), 'data');
    const dataDir = fs.existsSync(backendDataDir)
      ? backendDataDir
      : fs.existsSync(localDataDir)
      ? localDataDir
      : fs.existsSync(path.resolve(process.cwd(), 'backend'))
      ? backendDataDir
      : localDataDir;

    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    const isTestEnv = process.env.NODE_ENV === 'test' || process.argv.some((arg) => arg.includes('test'));
    const dbFileName = isTestEnv ? 'cyberguard_test.db' : 'cyberguard_vulnerabilities.db';
    this.dbPath = process.env.CYBERGUARD_DB_PATH || path.join(dataDir, dbFileName);
    this.db = new Database(this.dbPath);
    this.db.pragma('journal_mode = WAL');
    this.initTables();
    this.seedDefaultsIfEmpty();
    this.seedBankingDataIfEmpty();
  }

  private initTables() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
        status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'locked', 'reset_required')),
        mfa_required INTEGER NOT NULL DEFAULT 0,
        privilege_level TEXT NOT NULL DEFAULT 'STANDARD' CHECK(privilege_level IN ('STANDARD', 'ELEVATED', 'ADMIN')),
        must_reset INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS login_attempts (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        email TEXT NOT NULL,
        org_id TEXT NOT NULL,
        success INTEGER NOT NULL,
        ip_address TEXT NOT NULL,
        device_fingerprint TEXT NOT NULL,
        location TEXT NOT NULL,
        failure_reason TEXT,
        timestamp TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS blocked_entities (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        entity_type TEXT NOT NULL CHECK(entity_type IN ('IP', 'DEVICE')),
        entity_value TEXT NOT NULL,
        blocked_by TEXT NOT NULL,
        blocked_at TEXT NOT NULL,
        reason TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS account_notices (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        notice_type TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at TEXT NOT NULL,
        acknowledged INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id)
      );

      CREATE TABLE IF NOT EXISTS account_alerts (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        user_email TEXT NOT NULL,
        user_name TEXT NOT NULL,
        org_id TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('New', 'Investigating', 'Remediated')),
        severity TEXT NOT NULL CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
        confidence INTEGER NOT NULL,
        title TEXT NOT NULL,
        summary TEXT NOT NULL,
        matched_rules TEXT NOT NULL,
        factor_contributions TEXT NOT NULL,
        account_risk_score INTEGER NOT NULL,
        recommended_fixes TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        remediated_at TEXT,
        remediated_by TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
      );

      CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        hostname TEXT NOT NULL,
        os TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('Healthy', 'Suspicious', 'Compromised', 'Isolated', 'Remediated', 'Offline')),
        risk INTEGER NOT NULL DEFAULT 15,
        last_seen TEXT NOT NULL,
        enrolled_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
      );

      CREATE TABLE IF NOT EXISTS device_secrets (
        device_id TEXT PRIMARY KEY,
        token_hash TEXT NOT NULL,
        command_secret TEXT NOT NULL,
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS device_events (
        id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        details TEXT NOT NULL,
        severity TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS commands (
        id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        action TEXT NOT NULL,
        params TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('Pending', 'Sent', 'Executed', 'Failed', 'Rejected')),
        issued_by TEXT NOT NULL,
        issued_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        nonce TEXT NOT NULL,
        signature TEXT NOT NULL,
        result TEXT,
        result_at TEXT,
        FOREIGN KEY (device_id) REFERENCES devices(id)
      );

      CREATE TABLE IF NOT EXISTS audit_log (
        id TEXT PRIMARY KEY,
        ts TEXT NOT NULL,
        actor TEXT NOT NULL,
        org_id TEXT NOT NULL,
        device_id TEXT,
        action TEXT NOT NULL,
        details TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        hash TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        token_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        revoked_at TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
      );

      CREATE TABLE IF NOT EXISTS enrollment_codes (
        code TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id)
      );

      CREATE TABLE IF NOT EXISTS organizations (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        join_code TEXT UNIQUE NOT NULL,
        requires_approval INTEGER NOT NULL DEFAULT 0,
        opted_in_collaborative INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS bank_assets (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        description TEXT NOT NULL,
        criticality TEXT NOT NULL CHECK(criticality IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
        ip_or_identifier TEXT NOT NULL,
        technology_stack TEXT NOT NULL,
        owner_department TEXT NOT NULL,
        security_status TEXT NOT NULL CHECK(security_status IN ('HEALTHY', 'DEGRADED', 'AT_RISK', 'COMPROMISED', 'MAINTENANCE')),
        associated_vulns_count INTEGER NOT NULL DEFAULT 0,
        last_assessment_date TEXT NOT NULL,
        risk_score INTEGER NOT NULL DEFAULT 25,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS bank_security_events (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        affected_asset_id TEXT NOT NULL,
        event_category TEXT NOT NULL,
        severity TEXT NOT NULL CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
        timestamp TEXT NOT NULL,
        description TEXT NOT NULL,
        detection_source TEXT NOT NULL,
        investigation_status TEXT NOT NULL CHECK(investigation_status IN ('NEW', 'INVESTIGATING', 'CONTAINED', 'RESOLVED')),
        recommended_action TEXT NOT NULL,
        FOREIGN KEY (affected_asset_id) REFERENCES bank_assets(id)
      );

      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_orgs_join_code ON organizations(join_code);
      CREATE INDEX IF NOT EXISTS idx_devices_org ON devices(org_id);
      CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);
      CREATE INDEX IF NOT EXISTS idx_commands_device ON commands(device_id);
      CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_log(org_id);
      CREATE INDEX IF NOT EXISTS idx_audit_device ON audit_log(device_id);
      CREATE INDEX IF NOT EXISTS idx_login_attempts_email ON login_attempts(email);
      CREATE INDEX IF NOT EXISTS idx_login_attempts_org ON login_attempts(org_id);
      CREATE INDEX IF NOT EXISTS idx_login_attempts_time ON login_attempts(timestamp);
      CREATE INDEX IF NOT EXISTS idx_blocked_val ON blocked_entities(entity_value);
      CREATE INDEX IF NOT EXISTS idx_notices_user ON account_notices(user_id);
      CREATE INDEX IF NOT EXISTS idx_alerts_user ON account_alerts(user_id);
      CREATE INDEX IF NOT EXISTS idx_alerts_org ON account_alerts(org_id);
      CREATE INDEX IF NOT EXISTS idx_alerts_status ON account_alerts(status);
      CREATE INDEX IF NOT EXISTS idx_bank_assets_org ON bank_assets(org_id);
      CREATE INDEX IF NOT EXISTS idx_bank_assets_crit ON bank_assets(criticality);
      CREATE INDEX IF NOT EXISTS idx_bank_events_org ON bank_security_events(org_id);
      CREATE INDEX IF NOT EXISTS idx_bank_events_asset ON bank_security_events(affected_asset_id);
      CREATE INDEX IF NOT EXISTS idx_bank_events_status ON bank_security_events(investigation_status);
    `);

    try { this.db.exec("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active';"); } catch {}
    try { this.db.exec("ALTER TABLE users ADD COLUMN mfa_required INTEGER NOT NULL DEFAULT 0;"); } catch {}
    try { this.db.exec("ALTER TABLE users ADD COLUMN privilege_level TEXT NOT NULL DEFAULT 'STANDARD';"); } catch {}
    try { this.db.exec("UPDATE organizations SET name = 'Demo Bank', type = 'Banking and Financial Services' WHERE id = 'org-1';"); } catch {}
  }

  public seedDefaultsIfEmpty() {
    const orgCount = this.db.prepare('SELECT COUNT(*) as count FROM organizations').get() as { count: number };
    if (orgCount.count === 0) {
      const now = new Date().toISOString();
      const insertOrg = this.db.prepare(`
        INSERT OR REPLACE INTO organizations (id, name, type, join_code, requires_approval, opted_in_collaborative, created_at)
        VALUES (@id, @name, @type, @join_code, @requires_approval, @opted_in_collaborative, @created_at)
      `);
      insertOrg.run({ id: 'org-1', name: 'Bank A', type: 'Financial Services', join_code: 'BANK-A01', requires_approval: 0, opted_in_collaborative: 1, created_at: now });
      insertOrg.run({ id: 'org-2', name: 'Hospital B', type: 'Healthcare & Lifesciences', join_code: 'HOSP-B02', requires_approval: 0, opted_in_collaborative: 1, created_at: now });
      insertOrg.run({ id: 'org-3', name: 'University C', type: 'Education & Research', join_code: 'UNIV-C03', requires_approval: 0, opted_in_collaborative: 1, created_at: now });
    }

    const userCount = (this.db.prepare('SELECT COUNT(*) as count FROM users').get() as { count: number }).count;
    if (userCount === 0) {
      console.log('🌱 [EndpointDb] Seeding prototype users...');
      const now = new Date().toISOString();
      const adminPassHash = bcrypt.hashSync('AdminPass123!', 10);
      const userPassHash = bcrypt.hashSync('UserPass123!', 10);

      const usersToInsert: UserRecord[] = [
        // Bank A (org-1)
        { id: 'usr-bank-admin', org_id: 'org-1', name: 'Bank A Admin', email: 'admin@banka.com', password_hash: adminPassHash, role: 'admin', status: 'active', mfa_required: 0, privilege_level: 'ADMIN', must_reset: 0, created_at: now },
        { id: 'usr-bank-portal-test', org_id: 'org-1', name: 'Portal Test User', email: 'user_portal_test@banka.com', password_hash: userPassHash, role: 'user', status: 'active', mfa_required: 0, privilege_level: 'STANDARD', must_reset: 0, created_at: now },
        { id: 'usr-bank-attack-target', org_id: 'org-1', name: 'Red Team Target (Sandbox)', email: 'attack_target@banka.com', password_hash: userPassHash, role: 'user', status: 'active', mfa_required: 0, privilege_level: 'STANDARD', must_reset: 0, created_at: now },
        { id: 'usr-bank-alice', org_id: 'org-1', name: 'Alice Walker', email: 'alice@banka.com', password_hash: userPassHash, role: 'user', status: 'active', mfa_required: 0, privilege_level: 'STANDARD', must_reset: 0, created_at: now },
        { id: 'usr-bank-bob', org_id: 'org-1', name: 'Bob Miller', email: 'bob@banka.com', password_hash: userPassHash, role: 'user', status: 'active', mfa_required: 0, privilege_level: 'ELEVATED', must_reset: 0, created_at: now },

        // Hospital B (org-2)
        { id: 'usr-hosp-admin', org_id: 'org-2', name: 'Hospital B Admin', email: 'admin@hospitalb.org', password_hash: adminPassHash, role: 'admin', status: 'active', mfa_required: 0, privilege_level: 'ADMIN', must_reset: 0, created_at: now },
        { id: 'usr-hosp-clara', org_id: 'org-2', name: 'Dr. Clara Oswald', email: 'clara@hospitalb.org', password_hash: userPassHash, role: 'user', status: 'active', mfa_required: 0, privilege_level: 'STANDARD', must_reset: 0, created_at: now },
        { id: 'usr-hosp-david', org_id: 'org-2', name: 'David Kim', email: 'david@hospitalb.org', password_hash: userPassHash, role: 'user', status: 'active', mfa_required: 0, privilege_level: 'STANDARD', must_reset: 0, created_at: now },

        // University C (org-3)
        { id: 'usr-univ-admin', org_id: 'org-3', name: 'Univ C Admin', email: 'admin@univc.edu', password_hash: adminPassHash, role: 'admin', status: 'active', mfa_required: 0, privilege_level: 'ADMIN', must_reset: 0, created_at: now },
        { id: 'usr-univ-emma', org_id: 'org-3', name: 'Prof. Emma Watson', email: 'emma@univc.edu', password_hash: userPassHash, role: 'user', status: 'active', mfa_required: 0, privilege_level: 'STANDARD', must_reset: 0, created_at: now },
        { id: 'usr-univ-frank', org_id: 'org-3', name: 'Frank Underhill', email: 'frank@univc.edu', password_hash: userPassHash, role: 'user', status: 'active', mfa_required: 0, privilege_level: 'STANDARD', must_reset: 0, created_at: now },
      ];

      const insertUser = this.db.prepare(`
        INSERT OR REPLACE INTO users (id, org_id, name, email, password_hash, role, status, mfa_required, privilege_level, must_reset, created_at)
        VALUES (@id, @org_id, @name, @email, @password_hash, @role, @status, @mfa_required, @privilege_level, @must_reset, @created_at)
      `);

      for (const u of usersToInsert) {
        insertUser.run(u);
      }
    }

    const deviceCount = (this.db.prepare('SELECT COUNT(*) as count FROM devices').get() as { count: number }).count;
    if (deviceCount === 0) {
      console.log('💻 [EndpointDb] Seeding prototype devices...');
      const now = new Date().toISOString();

    const devicesToInsert: Array<DeviceRecord & { command_secret: string; token: string }> = [
      {
        id: 'DEV-BANK-01',
        org_id: 'org-1',
        user_id: 'usr-bank-alice',
        hostname: 'ALICE-LAPTOP-W11',
        os: 'Windows 11 Enterprise',
        status: 'Healthy',
        risk: 18,
        last_seen: now,
        enrolled_at: now,
        command_secret: 'secret-cmd-bank-dev-01-prototype',
        token: 'devtoken-bank-01-prototype'
      },
      {
        id: 'DEV-BANK-02',
        org_id: 'org-1',
        user_id: 'usr-bank-bob',
        hostname: 'BOB-FIN-WS02',
        os: 'Windows 11 Pro',
        status: 'Healthy',
        risk: 22,
        last_seen: now,
        enrolled_at: now,
        command_secret: 'secret-cmd-bank-dev-02-prototype',
        token: 'devtoken-bank-02-prototype'
      },
      {
        id: 'DEV-HOSP-01',
        org_id: 'org-2',
        user_id: 'usr-hosp-clara',
        hostname: 'CLARA-MED-TABLET',
        os: 'Windows 11 Medical',
        status: 'Healthy',
        risk: 15,
        last_seen: now,
        enrolled_at: now,
        command_secret: 'secret-cmd-hosp-dev-01-prototype',
        token: 'devtoken-hosp-01-prototype'
      },
      {
        id: 'DEV-HOSP-02',
        org_id: 'org-2',
        user_id: 'usr-hosp-david',
        hostname: 'NURSE-STATION-04',
        os: 'Windows 10 Enterprise',
        status: 'Healthy',
        risk: 20,
        last_seen: now,
        enrolled_at: now,
        command_secret: 'secret-cmd-hosp-dev-02-prototype',
        token: 'devtoken-hosp-02-prototype'
      },
      {
        id: 'DEV-UNIV-01',
        org_id: 'org-3',
        user_id: 'usr-univ-emma',
        hostname: 'EMMA-RESEARCH-LAB',
        os: 'Ubuntu 22.04 LTS',
        status: 'Healthy',
        risk: 14,
        last_seen: now,
        enrolled_at: now,
        command_secret: 'secret-cmd-univ-dev-01-prototype',
        token: 'devtoken-univ-01-prototype'
      },
      {
        id: 'DEV-UNIV-02',
        org_id: 'org-3',
        user_id: 'usr-univ-frank',
        hostname: 'FRANK-ENG-DESK',
        os: 'macOS Sonoma',
        status: 'Healthy',
        risk: 19,
        last_seen: now,
        enrolled_at: now,
        command_secret: 'secret-cmd-univ-dev-02-prototype',
        token: 'devtoken-univ-02-prototype'
      }
    ];

    const insertDevice = this.db.prepare(`
      INSERT OR REPLACE INTO devices (id, org_id, user_id, hostname, os, status, risk, last_seen, enrolled_at)
      VALUES (@id, @org_id, @user_id, @hostname, @os, @status, @risk, @last_seen, @enrolled_at)
    `);

    const insertSecret = this.db.prepare(`
      INSERT OR REPLACE INTO device_secrets (device_id, token_hash, command_secret)
      VALUES (?, ?, ?)
    `);

    for (const d of devicesToInsert) {
      insertDevice.run({
        id: d.id,
        org_id: d.org_id,
        user_id: d.user_id,
        hostname: d.hostname,
        os: d.os,
        status: d.status,
        risk: d.risk,
        last_seen: d.last_seen,
        enrolled_at: d.enrolled_at
      });

      const tokenHash = crypto.createHash('sha256').update(d.token).digest('hex');
      insertSecret.run(d.id, tokenHash, d.command_secret);
    }
  }

  const auditCount = (this.db.prepare('SELECT COUNT(*) as count FROM audit_log').get() as { count: number }).count;
  if (auditCount === 0) {
    // Genesis audit record
    const now = new Date().toISOString();
    const genesisPrevHash = '0000000000000000000000000000000000000000000000000000000000000000';
    const auditId = 'aud-genesis-001';
    const auditTs = now;
    const actor = 'system@cyberguard.local';
    const orgId = 'org-1';
    const action = 'SYSTEM_INIT';
    const details = 'CyberGuard Grid Endpoint Security Module initialized with baseline devices and verified role credentials.';
    const hash = computeAuditHash(auditId, auditTs, actor, orgId, null, action, details, genesisPrevHash);

    this.db.prepare(`
      INSERT OR REPLACE INTO audit_log (id, ts, actor, org_id, device_id, action, details, prev_hash, hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(auditId, auditTs, actor, orgId, null, action, details, genesisPrevHash, hash);
  }
}

  // Organization Operations
  public getOrgById(id: string): OrganizationRecord | undefined {
    return this.db.prepare('SELECT * FROM organizations WHERE id = ?').get(id) as OrganizationRecord | undefined;
  }

  public getOrgByJoinCode(code: string): OrganizationRecord | undefined {
    return this.db.prepare('SELECT * FROM organizations WHERE UPPER(join_code) = UPPER(?)').get(code.trim()) as OrganizationRecord | undefined;
  }

  public getAllOrganizations(): OrganizationRecord[] {
    return this.db.prepare('SELECT * FROM organizations ORDER BY name ASC').all() as OrganizationRecord[];
  }

  public saveOrganization(org: OrganizationRecord) {
    this.db.prepare(`
      INSERT OR REPLACE INTO organizations (id, name, type, join_code, requires_approval, opted_in_collaborative, created_at)
      VALUES (@id, @name, @type, @join_code, @requires_approval, @opted_in_collaborative, @created_at)
    `).run(org);
  }

  public updateOrgJoinCode(orgId: string, joinCode: string) {
    this.db.prepare('UPDATE organizations SET join_code = ? WHERE id = ?').run(joinCode, orgId);
  }

  public updateOrgSettings(orgId: string, settings: { requiresApproval?: boolean; optedInCollaborative?: boolean }) {
    if (settings.requiresApproval !== undefined) {
      this.db.prepare('UPDATE organizations SET requires_approval = ? WHERE id = ?').run(settings.requiresApproval ? 1 : 0, orgId);
    }
    if (settings.optedInCollaborative !== undefined) {
      this.db.prepare('UPDATE organizations SET opted_in_collaborative = ? WHERE id = ?').run(settings.optedInCollaborative ? 1 : 0, orgId);
    }
  }

  // User Operations
  public getUserByEmail(email: string): UserRecord | undefined {
    return this.db.prepare('SELECT * FROM users WHERE LOWER(email) = LOWER(?)').get(email.trim()) as UserRecord | undefined;
  }

  public getUserById(id: string): UserRecord | undefined {
    return this.db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRecord | undefined;
  }

  public createUser(user: UserRecord) {
    this.db.prepare(`
      INSERT INTO users (id, org_id, name, email, password_hash, role, status, mfa_required, privilege_level, must_reset, created_at)
      VALUES (@id, @org_id, @name, @email, @password_hash, @role, @status, @mfa_required, @privilege_level, @must_reset, @created_at)
    `).run(user);
  }

  public updateUserRole(userId: string, role: 'admin' | 'user', privilegeLevel?: string) {
    const priv = privilegeLevel || (role === 'admin' ? 'ADMIN' : 'STANDARD');
    this.db.prepare('UPDATE users SET role = ?, privilege_level = ? WHERE id = ?').run(role, priv, userId);
  }

  public countAdminsInOrg(orgId: string): number {
    const row = this.db.prepare("SELECT COUNT(*) as count FROM users WHERE org_id = ? AND role = 'admin' AND status = 'active'").get(orgId) as { count: number };
    return row ? row.count : 0;
  }

  public updateUserMustReset(id: string, mustReset: boolean) {
    this.db.prepare('UPDATE users SET must_reset = ? WHERE id = ?').run(mustReset ? 1 : 0, id);
  }

  public updateUserPassword(id: string, newPasswordHash: string) {
    this.db.prepare('UPDATE users SET password_hash = ?, status = \'active\', must_reset = 0 WHERE id = ?').run(newPasswordHash, id);
  }

  // Account Operations (Module 8 Phase 1)
  public getUsersByOrg(orgId: string): UserRecord[] {
    return this.db.prepare('SELECT * FROM users WHERE org_id = ? ORDER BY role DESC, name ASC').all(orgId) as UserRecord[];
  }

  public updateUserStatus(userId: string, status: 'active' | 'locked' | 'reset_required' | 'pending') {
    const mustReset = status === 'reset_required' ? 1 : 0;
    this.db.prepare('UPDATE users SET status = ?, must_reset = ? WHERE id = ?').run(status, mustReset, userId);
  }

  public updateUserMfa(userId: string, mfaRequired: boolean) {
    this.db.prepare('UPDATE users SET mfa_required = ? WHERE id = ?').run(mfaRequired ? 1 : 0, userId);
  }

  public updateUserPrivilege(userId: string, privilegeLevel: 'STANDARD' | 'ELEVATED' | 'ADMIN') {
    this.db.prepare('UPDATE users SET privilege_level = ? WHERE id = ?').run(privilegeLevel, userId);
  }

  public recordLoginAttempt(record: LoginAttemptRecord) {
    this.db.prepare(`
      INSERT OR REPLACE INTO login_attempts (id, user_id, email, org_id, success, ip_address, device_fingerprint, location, failure_reason, timestamp)
      VALUES (@id, @user_id, @email, @org_id, @success, @ip_address, @device_fingerprint, @location, @failure_reason, @timestamp)
    `).run(record);
  }

  public getRecentLoginAttempts(userEmailOrId: string, limit = 20): LoginAttemptRecord[] {
    return this.db.prepare(`
      SELECT * FROM login_attempts
      WHERE email = ? OR user_id = ?
      ORDER BY timestamp DESC
      LIMIT ?
    `).all(userEmailOrId, userEmailOrId, limit) as LoginAttemptRecord[];
  }

  public getLoginAttemptsByOrg(orgId: string, limit = 50): LoginAttemptRecord[] {
    return this.db.prepare(`
      SELECT * FROM login_attempts
      WHERE org_id = ?
      ORDER BY timestamp DESC
      LIMIT ?
    `).all(orgId, limit) as LoginAttemptRecord[];
  }

  public isEntityBlocked(orgId: string, ip: string, device: string): { blocked: boolean; reason?: string } {
    // Loopback/local development addresses must never be blocked at perimeter
    const effectiveIp = (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') ? '__loopback_whitelisted__' : ip;

    const found = this.db.prepare(`
      SELECT * FROM blocked_entities
      WHERE org_id = ? AND (
        (entity_type = 'IP' AND entity_value = ?) OR
        (entity_type = 'DEVICE' AND entity_value = ?)
      )
      LIMIT 1
    `).get(orgId, effectiveIp, device) as BlockedEntityRecord | undefined;

    if (found) {
      return { blocked: true, reason: found.reason };
    }
    return { blocked: false };
  }

  public blockEntity(orgId: string, entityType: 'IP' | 'DEVICE', value: string, blockedBy: string, reason: string) {
    const id = `blk-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
    const now = new Date().toISOString();
    this.db.prepare(`
      INSERT OR REPLACE INTO blocked_entities (id, org_id, entity_type, entity_value, blocked_by, blocked_at, reason)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, orgId, entityType, value, blockedBy, now, reason);
  }

  public unblockEntity(orgId: string, entityType: 'IP' | 'DEVICE', value: string) {
    this.db.prepare(`
      DELETE FROM blocked_entities
      WHERE org_id = ? AND entity_type = ? AND entity_value = ?
    `).run(orgId, entityType, value);
  }

  public getBlockedEntities(orgId: string): BlockedEntityRecord[] {
    return this.db.prepare('SELECT * FROM blocked_entities WHERE org_id = ? ORDER BY blocked_at DESC').all(orgId) as BlockedEntityRecord[];
  }

  public addAccountNotice(userId: string, orgId: string, noticeType: string, message: string) {
    const id = `notif-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
    const now = new Date().toISOString();
    this.db.prepare(`
      INSERT INTO account_notices (id, user_id, org_id, notice_type, message, created_at, acknowledged)
      VALUES (?, ?, ?, ?, ?, ?, 0)
    `).run(id, userId, orgId, noticeType, message, now);
  }

  public getAccountNotices(userId: string): AccountNoticeRecord[] {
    return this.db.prepare('SELECT * FROM account_notices WHERE user_id = ? AND acknowledged = 0 ORDER BY created_at DESC').all(userId) as AccountNoticeRecord[];
  }

  public dismissAccountNotice(noticeId: string) {
    this.db.prepare('UPDATE account_notices SET acknowledged = 1 WHERE id = ?').run(noticeId);
  }

  // Account Alerts Operations (Module 8 Phase 2)
  public saveAccountAlert(alert: AccountAlertRecord) {
    this.db.prepare(`
      INSERT OR REPLACE INTO account_alerts (
        id, user_id, user_email, user_name, org_id, status, severity, confidence,
        title, summary, matched_rules, factor_contributions, account_risk_score,
        recommended_fixes, timestamp, remediated_at, remediated_by
      ) VALUES (
        @id, @user_id, @user_email, @user_name, @org_id, @status, @severity, @confidence,
        @title, @summary, @matched_rules, @factor_contributions, @account_risk_score,
        @recommended_fixes, @timestamp, @remediated_at, @remediated_by
      )
    `).run(alert);
  }

  public getAccountAlertsByOrg(orgId: string): AccountAlertRecord[] {
    return this.db.prepare('SELECT * FROM account_alerts WHERE org_id = ? ORDER BY timestamp DESC').all(orgId) as AccountAlertRecord[];
  }

  public getAccountAlertById(id: string): AccountAlertRecord | undefined {
    return this.db.prepare('SELECT * FROM account_alerts WHERE id = ?').get(id) as AccountAlertRecord | undefined;
  }

  public getAccountAlertByUserId(userId: string): AccountAlertRecord | undefined {
    return this.db.prepare('SELECT * FROM account_alerts WHERE user_id = ? ORDER BY timestamp DESC LIMIT 1').get(userId) as AccountAlertRecord | undefined;
  }

  public getUserReports(userId: string): AccountAlertRecord[] {
    return this.db.prepare("SELECT * FROM account_alerts WHERE user_id = ? AND title LIKE '%REPORT%' ORDER BY timestamp DESC LIMIT 20").all(userId) as AccountAlertRecord[];
  }

  public updateAccountAlertStatus(id: string, status: 'New' | 'Investigating' | 'Remediated', remediatedBy?: string) {
    const now = new Date().toISOString();
    if (status === 'Remediated') {
      this.db.prepare('UPDATE account_alerts SET status = ?, remediated_at = ?, remediated_by = ? WHERE id = ?').run(status, now, remediatedBy || 'soc_admin', id);
    } else {
      this.db.prepare('UPDATE account_alerts SET status = ? WHERE id = ?').run(status, id);
    }
  }

  // Device Operations
  public getDevicesByOrg(orgId: string): Array<DeviceRecord & { user_email: string; user_name: string }> {
    return this.db.prepare(`
      SELECT d.*, u.email as user_email, u.name as user_name
      FROM devices d
      JOIN users u ON d.user_id = u.id
      WHERE d.org_id = ?
      ORDER BY d.risk DESC
    `).all(orgId) as any[];
  }

  public getDeviceById(deviceId: string): (DeviceRecord & { user_email: string; user_name: string }) | undefined {
    return this.db.prepare(`
      SELECT d.*, u.email as user_email, u.name as user_name
      FROM devices d
      JOIN users u ON d.user_id = u.id
      WHERE d.id = ?
    `).get(deviceId) as any;
  }

  public getDeviceByUserId(userId: string): (DeviceRecord & { user_email: string; user_name: string }) | undefined {
    return this.db.prepare(`
      SELECT d.*, u.email as user_email, u.name as user_name
      FROM devices d
      JOIN users u ON d.user_id = u.id
      WHERE d.user_id = ?
    `).get(userId) as any;
  }

  public updateDeviceStatus(deviceId: string, status: DeviceRecord['status'], risk?: number) {
    const now = new Date().toISOString();
    if (risk !== undefined) {
      this.db.prepare('UPDATE devices SET status = ?, risk = ?, last_seen = ? WHERE id = ?').run(status, risk, now, deviceId);
    } else {
      this.db.prepare('UPDATE devices SET status = ?, last_seen = ? WHERE id = ?').run(status, now, deviceId);
    }
  }

  public updateDeviceHeartbeat(deviceId: string) {
    this.db.prepare('UPDATE devices SET last_seen = ? WHERE id = ?').run(new Date().toISOString(), deviceId);
  }

  public getDeviceSecret(deviceId: string): DeviceSecretRecord | undefined {
    return this.db.prepare('SELECT * FROM device_secrets WHERE device_id = ?').get(deviceId) as DeviceSecretRecord | undefined;
  }

  public verifyDeviceToken(deviceId: string, token: string): boolean {
    const secret = this.getDeviceSecret(deviceId);
    if (!secret) return false;
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    return secret.token_hash === tokenHash;
  }

  public registerDevice(device: DeviceRecord, commandSecret: string, token: string) {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const insertDevice = this.db.prepare(`
      INSERT OR REPLACE INTO devices (id, org_id, user_id, hostname, os, status, risk, last_seen, enrolled_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const insertSecret = this.db.prepare(`
      INSERT OR REPLACE INTO device_secrets (device_id, token_hash, command_secret)
      VALUES (?, ?, ?)
    `);

    const transaction = this.db.transaction(() => {
      insertDevice.run(device.id, device.org_id, device.user_id, device.hostname, device.os, device.status, device.risk, device.last_seen, device.enrolled_at);
      insertSecret.run(device.id, tokenHash, commandSecret);
    });
    transaction();
  }

  // Enrollment Codes
  public createEnrollmentCode(orgId: string, userId: string, ttlMinutes = 60): string {
    const code = `CG-${crypto.randomBytes(3).toString('hex').toUpperCase()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    const now = new Date();
    const expires = new Date(now.getTime() + ttlMinutes * 60 * 1000);
    this.db.prepare(`
      INSERT INTO enrollment_codes (code, org_id, user_id, created_at, expires_at, used)
      VALUES (?, ?, ?, ?, ?, 0)
    `).run(code, orgId, userId, now.toISOString(), expires.toISOString());
    return code;
  }

  public consumeEnrollmentCode(code: string): EnrollmentCodeRecord | null {
    const record = this.db.prepare('SELECT * FROM enrollment_codes WHERE code = ? AND used = 0').get(code) as EnrollmentCodeRecord | undefined;
    if (!record) return null;
    if (new Date(record.expires_at).getTime() < Date.now()) return null;

    this.db.prepare('UPDATE enrollment_codes SET used = 1 WHERE code = ?').run(code);
    return record;
  }

  // Commands
  public recordCommand(command: CommandRecord) {
    this.db.prepare(`
      INSERT OR REPLACE INTO commands (id, device_id, action, params, status, issued_by, issued_at, expires_at, nonce, signature, result, result_at)
      VALUES (@id, @device_id, @action, @params, @status, @issued_by, @issued_at, @expires_at, @nonce, @signature, @result, @result_at)
    `).run(command);
  }

  public updateCommandStatus(commandId: string, status: CommandRecord['status'], result?: string) {
    const now = new Date().toISOString();
    this.db.prepare(`
      UPDATE commands SET status = ?, result = COALESCE(?, result), result_at = ? WHERE id = ?
    `).run(status, result || null, now, commandId);
  }

  public getCommandsForDevice(deviceId: string): CommandRecord[] {
    return this.db.prepare('SELECT * FROM commands WHERE device_id = ? ORDER BY issued_at DESC').all(deviceId) as CommandRecord[];
  }

  public getPendingCommandsForDevice(deviceId: string): CommandRecord[] {
    return this.db.prepare(`
      SELECT * FROM commands
      WHERE device_id = ? AND status IN ('Pending', 'Sent')
      ORDER BY issued_at ASC
    `).all(deviceId) as CommandRecord[];
  }

  public getCommandByNonce(nonce: string): CommandRecord | undefined {
    return this.db.prepare('SELECT * FROM commands WHERE nonce = ?').get(nonce) as CommandRecord | undefined;
  }

  public getCommandById(id: string): CommandRecord | undefined {
    return this.db.prepare('SELECT * FROM commands WHERE id = ?').get(id) as CommandRecord | undefined;
  }

  // Device Events
  public recordDeviceEvent(event: DeviceEventRecord) {
    this.db.prepare(`
      INSERT INTO device_events (id, device_id, event_type, details, severity, timestamp)
      VALUES (@id, @device_id, @event_type, @details, @severity, @timestamp)
    `).run(event);
  }

  public getRecentDeviceEvents(deviceId: string, limit = 50): DeviceEventRecord[] {
    return this.db.prepare(`
      SELECT * FROM device_events WHERE device_id = ? ORDER BY timestamp DESC LIMIT ?
    `).all(deviceId, limit) as DeviceEventRecord[];
  }

  // Audit Log with Hash-Chain
  public appendAudit(actor: string, orgId: string, action: string, details: string, deviceId?: string | null): AuditRecord {
    const lastRecord = this.db.prepare('SELECT hash FROM audit_log ORDER BY rowid DESC LIMIT 1').get() as { hash: string } | undefined;
    const prevHash = lastRecord ? lastRecord.hash : '0000000000000000000000000000000000000000000000000000000000000000';
    const id = `aud-${Date.now()}-${(++this.auditSeq).toString(36)}`;
    const ts = new Date().toISOString();
    const hash = computeAuditHash(id, ts, actor, orgId, deviceId || null, action, details, prevHash);

    const record: AuditRecord = {
      id,
      ts,
      actor,
      org_id: orgId,
      device_id: deviceId || null,
      action,
      details,
      prev_hash: prevHash,
      hash
    };

    this.db.prepare(`
      INSERT INTO audit_log (id, ts, actor, org_id, device_id, action, details, prev_hash, hash)
      VALUES (@id, @ts, @actor, @org_id, @device_id, @action, @details, @prev_hash, @hash)
    `).run(record);

    return record;
  }

  public getAuditLogs(orgId?: string, limit = 100): AuditRecord[] {
    if (orgId && orgId !== 'all') {
      return this.db.prepare('SELECT * FROM audit_log WHERE org_id = ? ORDER BY rowid DESC LIMIT ?').all(orgId, limit) as AuditRecord[];
    }
    return this.db.prepare('SELECT * FROM audit_log ORDER BY rowid DESC LIMIT ?').all(limit) as AuditRecord[];
  }

  public verifyAuditChain(): { isVerified: boolean; brokenId: string | null; totalVerified: number; details: string } {
    const records = this.db.prepare('SELECT * FROM audit_log ORDER BY rowid ASC').all() as AuditRecord[];
    if (records.length === 0) {
      return { isVerified: true, brokenId: null, totalVerified: 0, details: 'Audit log is empty.' };
    }

    let prevHash = '0000000000000000000000000000000000000000000000000000000000000000';
    for (let i = 0; i < records.length; i++) {
      const rec = records[i];
      if (i > 0 && rec.prev_hash !== prevHash) {
        return {
          isVerified: false,
          brokenId: rec.id,
          totalVerified: i,
          details: `Linkage severed at record #${rec.id}: previous_hash pointer does not match previous block hash.`
        };
      }
      const expectedHash = computeAuditHash(rec.id, rec.ts, rec.actor, rec.org_id, rec.device_id, rec.action, rec.details, rec.prev_hash);
      if (expectedHash !== rec.hash) {
        return {
          isVerified: false,
          brokenId: rec.id,
          totalVerified: i,
          details: `Cryptographic tamper detected at record #${rec.id}: expected hash ${expectedHash.slice(0, 12)}..., stored ${rec.hash.slice(0, 12)}...`
        };
      }
      prevHash = rec.hash;
    }

    return {
      isVerified: true,
      brokenId: null,
      totalVerified: records.length,
      details: `Cryptographic hash chain verified successfully. All ${records.length} audit records are intact and tamper-evident.`
    };
  }

  public tamperAuditRecord(recordId?: string): { success: boolean; tamperedId: string; oldDetails: string; newDetails: string } {
    const target = recordId
      ? this.db.prepare('SELECT * FROM audit_log WHERE id = ?').get(recordId) as AuditRecord | undefined
      : this.db.prepare('SELECT * FROM audit_log ORDER BY rowid DESC LIMIT 1').get() as AuditRecord | undefined;

    if (!target) {
      throw new Error('No audit record found to tamper.');
    }

    const newDetails = target.details + ' [TAMPERED_BY_DEMO_ATTACKER: Unauthorized log payload injection]';
    this.db.prepare('UPDATE audit_log SET details = ? WHERE id = ?').run(newDetails, target.id);

    return {
      success: true,
      tamperedId: target.id,
      oldDetails: target.details,
      newDetails
    };
  }

  // Sessions
  public createSession(userId: string, token: string, ttlHours = 24): SessionRecord {
    const id = `ses-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttlHours * 60 * 60 * 1000).toISOString();

    const session: SessionRecord = {
      id,
      user_id: userId,
      token_hash: tokenHash,
      created_at: now.toISOString(),
      expires_at: expiresAt,
      revoked_at: null
    };

    this.db.prepare(`
      INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, revoked_at)
      VALUES (@id, @user_id, @token_hash, @created_at, @expires_at, @revoked_at)
    `).run(session);

    return session;
  }

  public revokeSession(token: string) {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    this.db.prepare('UPDATE sessions SET revoked_at = ? WHERE token_hash = ?').run(new Date().toISOString(), tokenHash);
  }

  public revokeAllUserSessions(userId: string) {
    this.db.prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').run(new Date().toISOString(), userId);
  }

  public revokeOtherSessions(userId: string, currentToken: string) {
    const tokenHash = crypto.createHash('sha256').update(currentToken).digest('hex');
    const now = new Date().toISOString();
    this.db.prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND token_hash != ? AND revoked_at IS NULL').run(now, userId, tokenHash);
  }

  public isSessionValid(token: string): boolean {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const session = this.db.prepare('SELECT * FROM sessions WHERE token_hash = ?').get(tokenHash) as SessionRecord | undefined;
    if (!session) return false;
    if (session.revoked_at) return false;
    return new Date(session.expires_at).getTime() > Date.now();
  }

  public getActiveSessions(userId: string): SessionRecord[] {
    const now = new Date().toISOString();
    return this.db.prepare('SELECT * FROM sessions WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?').all(userId, now) as SessionRecord[];
  }

  // Banking Security Edition Seeding
  public seedBankingDataIfEmpty() {
    try {
      this.db.prepare("UPDATE organizations SET name = 'Demo Bank', type = 'Banking and Financial Services' WHERE id = 'org-1'").run();
    } catch {}

    // Seed Demo Bank Admin if missing
    const existingDemoAdmin = this.db.prepare('SELECT id FROM users WHERE email = ?').get('admin@demobank.com');
    if (!existingDemoAdmin) {
      const adminPassHash = bcrypt.hashSync('AdminPass123!', 10);
      this.db.prepare(`
        INSERT OR REPLACE INTO users (id, org_id, name, email, password_hash, role, status, mfa_required, privilege_level, must_reset, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run('usr-bank-soc-admin', 'org-1', 'Bank SOC Administrator', 'admin@demobank.com', adminPassHash, 'admin', 'active', 0, 'ADMIN', 0, new Date().toISOString());
    }

    // Seed Portal Test User if missing (ensures employee portal user is always available without manual re-registration)
    const existingPortalUser = this.db.prepare('SELECT id FROM users WHERE email = ?').get('user_portal_test@banka.com');
    if (!existingPortalUser) {
      const userPassHash = bcrypt.hashSync('UserPass123!', 10);
      this.db.prepare(`
        INSERT OR REPLACE INTO users (id, org_id, name, email, password_hash, role, status, mfa_required, privilege_level, must_reset, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run('usr-bank-portal-test', 'org-1', 'Portal Test User', 'user_portal_test@banka.com', userPassHash, 'user', 'active', 0, 'STANDARD', 0, new Date().toISOString());
    }

    // Seed Dedicated Red Team / Attack Target Account if missing
    const existingAttackUser = this.db.prepare('SELECT id FROM users WHERE email = ?').get('attack_target@banka.com');
    if (!existingAttackUser) {
      const userPassHash = bcrypt.hashSync('UserPass123!', 10);
      this.db.prepare(`
        INSERT OR REPLACE INTO users (id, org_id, name, email, password_hash, role, status, mfa_required, privilege_level, must_reset, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run('usr-bank-attack-target', 'org-1', 'Red Team Target (Sandbox)', 'attack_target@banka.com', userPassHash, 'user', 'active', 0, 'STANDARD', 0, new Date().toISOString());
    }

    // Seed Baseline Login Attempts if empty
    const loginCount = (this.db.prepare('SELECT COUNT(*) as count FROM login_attempts').get() as { count: number }).count;
    if (loginCount === 0) {
      const insertLogin = this.db.prepare(`
        INSERT OR REPLACE INTO login_attempts (id, user_id, email, org_id, success, ip_address, device_fingerprint, location, failure_reason, timestamp)
        VALUES (@id, @user_id, @email, @org_id, @success, @ip_address, @device_fingerprint, @location, @failure_reason, @timestamp)
      `);
      const sampleAttempts: LoginAttemptRecord[] = [
        {
          id: 'att-init-portal-1',
          user_id: 'usr-bank-portal-test',
          email: 'user_portal_test@banka.com',
          org_id: 'org-1',
          success: 1,
          ip_address: '127.0.0.1',
          device_fingerprint: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0',
          location: 'New York, US',
          failure_reason: null,
          timestamp: new Date(Date.now() - 3600000).toISOString()
        },
        {
          id: 'att-init-portal-2',
          user_id: 'usr-bank-portal-test',
          email: 'user_portal_test@banka.com',
          org_id: 'org-1',
          success: 1,
          ip_address: '10.10.4.15',
          device_fingerprint: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/128.0',
          location: 'New York, US',
          failure_reason: null,
          timestamp: new Date(Date.now() - 86400000).toISOString()
        },
        {
          id: 'att-init-alice-1',
          user_id: 'usr-bank-alice',
          email: 'alice@banka.com',
          org_id: 'org-1',
          success: 1,
          ip_address: '10.10.4.22',
          device_fingerprint: 'ALICE-LAPTOP-W11 / Windows 11 Enterprise',
          location: 'New York, US',
          failure_reason: null,
          timestamp: new Date(Date.now() - 7200000).toISOString()
        },
        {
          id: 'att-init-bob-1',
          user_id: 'usr-bank-bob',
          email: 'bob@banka.com',
          org_id: 'org-1',
          success: 1,
          ip_address: '10.10.4.30',
          device_fingerprint: 'BOB-FIN-WS02 / Windows 11 Pro',
          location: 'New York, US',
          failure_reason: null,
          timestamp: new Date(Date.now() - 14400000).toISOString()
        },
        {
          id: 'att-init-admin-1',
          user_id: 'usr-bank-admin',
          email: 'admin@banka.com',
          org_id: 'org-1',
          success: 1,
          ip_address: '127.0.0.1',
          device_fingerprint: 'SOC-CONSOLE-W11 / Chrome 128.0',
          location: 'New York, US',
          failure_reason: null,
          timestamp: new Date(Date.now() - 1800000).toISOString()
        }
      ];
      for (const att of sampleAttempts) {
        insertLogin.run(att);
      }
    }

    // Seed Banking Assets if empty
    const assetCount = (this.db.prepare('SELECT COUNT(*) as count FROM bank_assets').get() as { count: number }).count;
    if (assetCount === 0) {
      console.log('🏦 [EndpointDb] Seeding 10 synthetic banking assets for Demo Bank (org-1)...');
      const now = new Date().toISOString();
      const assets: BankAssetRecord[] = [
        {
          id: 'asset-cbs',
          org_id: 'org-1',
          name: 'Core Banking System (Finacle CBS Cluster)',
          category: 'Core Banking',
          description: 'Central ledger and real-time transaction processing engine for savings, current accounts, and NEFT/RTGS clearing.',
          criticality: 'CRITICAL',
          ip_or_identifier: '10.10.1.50',
          technology_stack: 'Red Hat Enterprise Linux 9 / Finacle Core',
          owner_department: 'Core Banking Ops',
          security_status: 'HEALTHY',
          associated_vulns_count: 1,
          last_assessment_date: '2026-11-01',
          risk_score: 28,
          created_at: now,
          updated_at: now
        },
        {
          id: 'asset-netbank',
          org_id: 'org-1',
          name: 'Internet Banking Server',
          category: 'Internet Banking',
          description: 'Customer internet banking web portal, session authentication, and balance inquiry microservices.',
          criticality: 'CRITICAL',
          ip_or_identifier: '10.10.2.20',
          technology_stack: 'Ubuntu 22.04 LTS / Nginx Reverse Proxy',
          owner_department: 'Digital Banking',
          security_status: 'AT_RISK',
          associated_vulns_count: 4,
          last_assessment_date: '2026-11-02',
          risk_score: 65,
          created_at: now,
          updated_at: now
        },
        {
          id: 'asset-mobile',
          org_id: 'org-1',
          name: 'Mobile Banking Application Gateway',
          category: 'Mobile Banking',
          description: 'API gateway handling iOS and Android mobile banking traffic, biometrics, and MPIN verification.',
          criticality: 'HIGH',
          ip_or_identifier: '10.10.2.35',
          technology_stack: 'Kubernetes Microservices / Node.js & Go',
          owner_department: 'Digital Banking',
          security_status: 'HEALTHY',
          associated_vulns_count: 2,
          last_assessment_date: '2026-10-28',
          risk_score: 32,
          created_at: now,
          updated_at: now
        },
        {
          id: 'asset-atm',
          org_id: 'org-1',
          name: 'ATM Network Controller & Switch',
          category: 'ATM Infrastructure',
          description: 'Centralized switch interconnecting 450+ ATM kiosks with NPCI NFS switch and card authorization.',
          criticality: 'HIGH',
          ip_or_identifier: '10.20.5.10',
          technology_stack: 'Windows Server 2022 IoT / Base24-eps',
          owner_department: 'ATM Operations',
          security_status: 'HEALTHY',
          associated_vulns_count: 3,
          last_assessment_date: '2026-10-30',
          risk_score: 40,
          created_at: now,
          updated_at: now
        },
        {
          id: 'asset-payment',
          org_id: 'org-1',
          name: 'UPI & Payment Gateway Processor',
          category: 'Payment Gateway',
          description: 'High-throughput payment gateway processing IMPS, UPI 2.0, debit card clearing, and merchant settlement.',
          criticality: 'CRITICAL',
          ip_or_identifier: '10.10.3.15',
          technology_stack: 'Red Hat Enterprise Linux 8.8 / ISO 8583 Engine',
          owner_department: 'Payment Systems',
          security_status: 'COMPROMISED',
          associated_vulns_count: 7,
          last_assessment_date: '2026-11-02',
          risk_score: 88,
          created_at: now,
          updated_at: now
        },
        {
          id: 'asset-custdb',
          org_id: 'org-1',
          name: 'Customer Information Database (CIF)',
          category: 'Customer Database',
          description: 'Master repository for Customer Information Files (CIF), KYC documentation, Aadhaar/PAN tokens, and PII.',
          criticality: 'CRITICAL',
          ip_or_identifier: '10.10.4.10',
          technology_stack: 'Oracle Database 19c Enterprise RAC',
          owner_department: 'Data Governance & Compliance',
          security_status: 'HEALTHY',
          associated_vulns_count: 2,
          last_assessment_date: '2026-10-25',
          risk_score: 35,
          created_at: now,
          updated_at: now
        },
        {
          id: 'asset-workstations',
          org_id: 'org-1',
          name: 'Branch Employee Workstations Fleet',
          category: 'Workstations & Endpoints',
          description: 'Fleet of teller and branch manager desktop workstations across 24 regional branch offices.',
          criticality: 'MEDIUM',
          ip_or_identifier: '10.30.0.0/24',
          technology_stack: 'Windows 11 Enterprise (GPO Managed)',
          owner_department: 'IT Helpdesk & Branch Support',
          security_status: 'DEGRADED',
          associated_vulns_count: 5,
          last_assessment_date: '2026-10-29',
          risk_score: 58,
          created_at: now,
          updated_at: now
        },
        {
          id: 'asset-auth',
          org_id: 'org-1',
          name: 'Authentication Server & HSM Cluster',
          category: 'Authentication Server',
          description: 'Hardware Security Module (HSM) cluster for PIN verification, digital signatures, and banking PKI.',
          criticality: 'CRITICAL',
          ip_or_identifier: '10.10.1.12',
          technology_stack: 'Thales Luna HSM / FreeIPA Keycloak',
          owner_department: 'Information Security (CISO Office)',
          security_status: 'HEALTHY',
          associated_vulns_count: 0,
          last_assessment_date: '2026-11-01',
          risk_score: 22,
          created_at: now,
          updated_at: now
        },
        {
          id: 'asset-network',
          org_id: 'org-1',
          name: 'Bank Internal Core Network',
          category: 'Internal Network',
          description: 'Core MPLS and SD-WAN backbone linking data centers, disaster recovery sites, and branch offices.',
          criticality: 'HIGH',
          ip_or_identifier: '10.0.0.0/16',
          technology_stack: 'Cisco Catalyst SD-WAN / Palo Alto NGFW',
          owner_department: 'Network Infrastructure',
          security_status: 'HEALTHY',
          associated_vulns_count: 1,
          last_assessment_date: '2026-10-27',
          risk_score: 30,
          created_at: now,
          updated_at: now
        },
        {
          id: 'asset-dr',
          org_id: 'org-1',
          name: 'Backup & Disaster Recovery System',
          category: 'Disaster Recovery',
          description: 'Off-site disaster recovery site in Hyderabad with synchronous storage replication and immutable backups.',
          criticality: 'CRITICAL',
          ip_or_identifier: '10.50.1.10',
          technology_stack: 'Veeam Backup & Replication / Commvault / NetApp',
          owner_department: 'Business Continuity & DR',
          security_status: 'HEALTHY',
          associated_vulns_count: 0,
          last_assessment_date: '2026-10-26',
          risk_score: 20,
          created_at: now,
          updated_at: now
        }
      ];

      for (const a of assets) {
        this.saveBankAsset(a);
      }
    }

    // Seed Security Events if empty
    const eventCount = (this.db.prepare('SELECT COUNT(*) as count FROM bank_security_events').get() as { count: number }).count;
    if (eventCount === 0) {
      console.log('🚨 [EndpointDb] Seeding 5 initial banking security events for Demo Bank...');
      const now = new Date();
      const events: BankSecurityEventRecord[] = [
        {
          id: 'evt-001',
          org_id: 'org-1',
          affected_asset_id: 'asset-payment',
          event_category: 'Payment Fraud Anomaly',
          severity: 'CRITICAL',
          timestamp: new Date(now.getTime() - 12 * 60 * 1000).toISOString(),
          description: 'UPI velocity spike: 420 micro-debits/min originating from botnet proxies targeting merchant settlement account.',
          detection_source: 'UPI Transaction Sentry AI',
          investigation_status: 'INVESTIGATING',
          recommended_action: 'Trigger velocity throttling on suspect VPA endpoints and alert Fraud Monitoring Team.'
        },
        {
          id: 'evt-002',
          org_id: 'org-1',
          affected_asset_id: 'asset-netbank',
          event_category: 'Credential Stuffing',
          severity: 'HIGH',
          timestamp: new Date(now.getTime() - 45 * 60 * 1000).toISOString(),
          description: 'Distributed credential stuffing attack: 1,840 failed login attempts across 340 distinct proxy IPs within 5 minutes.',
          detection_source: 'WAF Rate Limiter & Threat Intel',
          investigation_status: 'CONTAINED',
          recommended_action: 'Enforce mandatory CAPTCHA and Step-Up OTP for affected IP CIDR blocks.'
        },
        {
          id: 'evt-003',
          org_id: 'org-1',
          affected_asset_id: 'asset-workstations',
          event_category: 'Endpoint Security',
          severity: 'MEDIUM',
          timestamp: new Date(now.getTime() - 3 * 3600 * 1000).toISOString(),
          description: 'Unauthorized USB mass storage device connected to Teller Workstation WS-04 at Connaught Place branch.',
          detection_source: 'Endpoint DLP Agent',
          investigation_status: 'RESOLVED',
          recommended_action: 'Device port blocked automatically by Group Policy and notified branch manager.'
        },
        {
          id: 'evt-004',
          org_id: 'org-1',
          affected_asset_id: 'asset-cbs',
          event_category: 'Unauthorized Access',
          severity: 'HIGH',
          timestamp: new Date(now.getTime() - 6 * 3600 * 1000).toISOString(),
          description: 'Bulk customer account balance query initiated outside normal clearing window (02:14 AM IST) from internal subnet.',
          detection_source: 'Database Activity Monitoring (DAM)',
          investigation_status: 'NEW',
          recommended_action: 'Verify audit authorization for query batch with Head of Core Operations.'
        },
        {
          id: 'evt-005',
          org_id: 'org-1',
          affected_asset_id: 'asset-atm',
          event_category: 'Network Telemetry',
          severity: 'LOW',
          timestamp: new Date(now.getTime() - 14 * 3600 * 1000).toISOString(),
          description: 'ATM Switch secondary route jitter (+140ms) detected on Western Zone multiplexer.',
          detection_source: 'Network Performance Monitor',
          investigation_status: 'RESOLVED',
          recommended_action: 'Failover switch route verified healthy; latency restored to under 12ms.'
        }
      ];

      for (const e of events) {
        this.saveBankSecurityEvent(e);
      }
    }
  }

  // Banking Asset CRUD Methods
  public getBankAssets(orgId: string): BankAssetRecord[] {
    return this.db.prepare('SELECT * FROM bank_assets WHERE org_id = ? ORDER BY risk_score DESC').all(orgId) as BankAssetRecord[];
  }

  public getBankAssetById(id: string): BankAssetRecord | undefined {
    return this.db.prepare('SELECT * FROM bank_assets WHERE id = ?').get(id) as BankAssetRecord | undefined;
  }

  public saveBankAsset(asset: BankAssetRecord): void {
    this.db.prepare(`
      INSERT OR REPLACE INTO bank_assets (
        id, org_id, name, category, description, criticality,
        ip_or_identifier, technology_stack, owner_department,
        security_status, associated_vulns_count, last_assessment_date,
        risk_score, created_at, updated_at
      ) VALUES (
        @id, @org_id, @name, @category, @description, @criticality,
        @ip_or_identifier, @technology_stack, @owner_department,
        @security_status, @associated_vulns_count, @last_assessment_date,
        @risk_score, @created_at, @updated_at
      )
    `).run(asset);
  }

  public updateBankAsset(id: string, updates: Partial<BankAssetRecord>): BankAssetRecord | undefined {
    const existing = this.getBankAssetById(id);
    if (!existing) return undefined;
    const updated: BankAssetRecord = {
      ...existing,
      ...updates,
      updated_at: new Date().toISOString()
    };
    this.saveBankAsset(updated);
    return updated;
  }

  public deleteBankAsset(id: string): boolean {
    const result = this.db.prepare('DELETE FROM bank_assets WHERE id = ?').run(id);
    return result.changes > 0;
  }

  // Banking Security Events CRUD Methods
  public getBankSecurityEvents(
    orgId: string,
    limit = 50,
    filters?: { severity?: string; assetId?: string; status?: string }
  ): (BankSecurityEventRecord & { affected_asset_name?: string })[] {
    let sql = `
      SELECT e.*, a.name as affected_asset_name
      FROM bank_security_events e
      LEFT JOIN bank_assets a ON e.affected_asset_id = a.id
      WHERE e.org_id = ?
    `;
    const params: any[] = [orgId];

    if (filters?.severity) {
      sql += ' AND e.severity = ?';
      params.push(filters.severity);
    }
    if (filters?.assetId) {
      sql += ' AND e.affected_asset_id = ?';
      params.push(filters.assetId);
    }
    if (filters?.status) {
      sql += ' AND e.investigation_status = ?';
      params.push(filters.status);
    }

    sql += ' ORDER BY e.timestamp DESC LIMIT ?';
    params.push(limit);

    return this.db.prepare(sql).all(...params) as (BankSecurityEventRecord & { affected_asset_name?: string })[];
  }

  public getBankSecurityEventById(id: string): (BankSecurityEventRecord & { affected_asset_name?: string }) | undefined {
    return this.db.prepare(`
      SELECT e.*, a.name as affected_asset_name
      FROM bank_security_events e
      LEFT JOIN bank_assets a ON e.affected_asset_id = a.id
      WHERE e.id = ?
    `).get(id) as (BankSecurityEventRecord & { affected_asset_name?: string }) | undefined;
  }

  public saveBankSecurityEvent(event: BankSecurityEventRecord): void {
    this.db.prepare(`
      INSERT OR REPLACE INTO bank_security_events (
        id, org_id, affected_asset_id, event_category, severity,
        timestamp, description, detection_source, investigation_status, recommended_action
      ) VALUES (
        @id, @org_id, @affected_asset_id, @event_category, @severity,
        @timestamp, @description, @detection_source, @investigation_status, @recommended_action
      )
    `).run(event);
  }

  public updateBankSecurityEventStatus(
    id: string,
    status: 'NEW' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED'
  ): (BankSecurityEventRecord & { affected_asset_name?: string }) | undefined {
    this.db.prepare('UPDATE bank_security_events SET investigation_status = ? WHERE id = ?').run(status, id);
    return this.getBankSecurityEventById(id);
  }

  // Reset to Baseline for Demo
  public resetToBaseline() {
    this.db.exec(`
      DELETE FROM commands;
      DELETE FROM device_events;
      DELETE FROM sessions;
      DELETE FROM enrollment_codes;
      DELETE FROM audit_log;
      DELETE FROM device_secrets;
      DELETE FROM devices;
      DELETE FROM blocked_entities;
      DELETE FROM account_notices;
      DELETE FROM account_alerts;
      DELETE FROM login_attempts WHERE success = 0;
    `);
    this.seedDefaultsIfEmpty();
    this.seedBankingDataIfEmpty();
    try {
      const adminPassHash = bcrypt.hashSync('AdminPass123!', 10);
      const userPassHash = bcrypt.hashSync('UserPass123!', 10);
      this.db.prepare("UPDATE users SET password_hash = ? WHERE role = 'admin' AND id LIKE 'usr-%'").run(adminPassHash);
      this.db.prepare("UPDATE users SET password_hash = ? WHERE role = 'user' AND id LIKE 'usr-%'").run(userPassHash);
      this.db.prepare("UPDATE users SET status = 'active', must_reset = 0, mfa_required = 0 WHERE id LIKE 'usr-%'").run();
      this.db.prepare("UPDATE users SET privilege_level = 'STANDARD' WHERE id IN ('usr-bank-alice', 'usr-bank-portal-test', 'usr-bank-attack-target', 'usr-hosp-clara', 'usr-hosp-david', 'usr-univ-emma', 'usr-univ-frank')").run();
      this.db.prepare("UPDATE users SET privilege_level = 'ELEVATED' WHERE id = 'usr-bank-bob'").run();
      this.db.prepare("UPDATE users SET privilege_level = 'ADMIN' WHERE role = 'admin'").run();
    } catch {}
  }
}

export const endpointDb = new EndpointDatabase();

