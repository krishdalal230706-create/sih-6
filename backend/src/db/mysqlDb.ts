import mysql, { Pool } from 'mysql2/promise';
import dotenv from 'dotenv';
import path from 'path';
import {
  VulnerabilityRecord,
  VulnerabilitySource,
  SyncLog,
  VulnerabilityFilterOptions,
  VulnerabilityStats
} from '../types/vulnerability.js';
import { calculateCyberGuardRisk } from '../services/riskPrioritization.js';

dotenv.config();
dotenv.config({ path: path.resolve(process.cwd(), '.env') });
dotenv.config({ path: path.resolve(process.cwd(), 'backend', '.env') });

const DB_HOST = process.env.DB_HOST || 'localhost';
const DB_PORT = parseInt(process.env.DB_PORT || '3306', 10);
const DB_NAME = process.env.DB_NAME || 'cyberguard_grid';
const DB_USER = process.env.DB_USER || 'root';
const DB_PASSWORD = process.env.DB_PASSWORD || '';

class MySqlVulnerabilityDatabase {
  private pool: Pool | null = null;
  private isConnected: boolean = false;

  constructor() {
    this.createPool();
  }

  private createPool() {
    try {
      this.pool = mysql.createPool({
        host: DB_HOST,
        port: DB_PORT,
        database: DB_NAME,
        user: DB_USER,
        password: DB_PASSWORD,
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0,
        connectTimeout: 3000
      });
    } catch (err: any) {
      this.pool = null;
      this.isConnected = false;
    }
  }

  public getIsConnected(): boolean {
    return this.isConnected;
  }

  public async testConnection(): Promise<boolean> {
    if (!this.pool) {
      this.createPool();
    }
    if (!this.pool) {
      console.error(`[MYSQL ERROR] Could not initialize MySQL pool for ${DB_HOST}:${DB_PORT}`);
      console.warn(`[MYSQL WARNING] Operating in fallback mode (embedded data layer active).`);
      this.isConnected = false;
      return false;
    }

    try {
      const conn = await this.pool.getConnection();
      await conn.ping();
      conn.release();

      this.isConnected = true;
      console.log('\n=======================================================');
      console.log('MySQL Connection: CONNECTED');
      console.log(`Database: ${DB_NAME}`);
      console.log('=======================================================\n');

      await this.ensureTablesExist();
      return true;
    } catch (err: any) {
      this.isConnected = false;
      console.error(`\n[MYSQL ERROR] Failed to connect to MySQL database at ${DB_HOST}:${DB_PORT}: ${err.message}`);
      console.warn(`[MYSQL WARNING] Falling back to embedded store until MySQL is available.\n`);
      return false;
    }
  }

  public async ensureTablesExist() {
    if (!this.pool || !this.isConnected) return;
    try {
      await this.pool.query(`
        CREATE TABLE IF NOT EXISTS vulnerabilities (
          id VARCHAR(64) PRIMARY KEY,
          cve_id VARCHAR(64) NOT NULL,
          title VARCHAR(512) NOT NULL,
          description TEXT NOT NULL,
          severity VARCHAR(32) NOT NULL,
          cvss_score DECIMAL(4,1) NOT NULL,
          cvss_vector VARCHAR(255),
          attack_vector VARCHAR(64),
          attack_complexity VARCHAR(64),
          privileges_required VARCHAR(64),
          user_interaction VARCHAR(64),
          affected_vendor VARCHAR(255) NOT NULL,
          affected_product VARCHAR(255) NOT NULL,
          affected_versions TEXT,
          published_date VARCHAR(64) NOT NULL,
          modified_date VARCHAR(64) NOT NULL,
          exploit_available TINYINT(1) NOT NULL DEFAULT 0,
          known_exploited TINYINT(1) NOT NULL DEFAULT 0,
          source VARCHAR(255) NOT NULL,
          references_json TEXT,
          \`references\` TEXT,
          remediation TEXT,
          last_updated VARCHAR(64) NOT NULL,
          cyberguard_priority VARCHAR(32) NOT NULL DEFAULT 'MEDIUM',
          cyberguard_score INT NOT NULL DEFAULT 50,
          confidence INT NOT NULL DEFAULT 80,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          CONSTRAINT uq_vuln_cve UNIQUE (cve_id)
        );
      `);

      await this.pool.query(`
        CREATE TABLE IF NOT EXISTS vulnerability_sources (
          id VARCHAR(64) PRIMARY KEY,
          name VARCHAR(255) NOT NULL,
          type VARCHAR(64) NOT NULL,
          url VARCHAR(512) NOT NULL,
          enabled TINYINT(1) NOT NULL DEFAULT 1,
          last_sync_at VARCHAR(64),
          sync_status VARCHAR(32) NOT NULL DEFAULT 'IDLE',
          error_message TEXT,
          records_count INT NOT NULL DEFAULT 0,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);

      await this.pool.query(`
        CREATE TABLE IF NOT EXISTS sync_logs (
          id VARCHAR(64) PRIMARY KEY,
          source_name VARCHAR(255) NOT NULL,
          status VARCHAR(32) NOT NULL,
          records_added INT NOT NULL DEFAULT 0,
          records_updated INT NOT NULL DEFAULT 0,
          records_skipped INT NOT NULL DEFAULT 0,
          error_count INT NOT NULL DEFAULT 0,
          error_details TEXT,
          duration_ms INT NOT NULL DEFAULT 0,
          created_at VARCHAR(64) NOT NULL
        );
      `);

      await this.pool.query(`
        CREATE TABLE IF NOT EXISTS affected_products (
          id VARCHAR(64) PRIMARY KEY,
          vulnerability_id VARCHAR(64) NOT NULL,
          cve_id VARCHAR(64) NOT NULL,
          vendor VARCHAR(255) NOT NULL,
          product VARCHAR(255) NOT NULL,
          versions TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);
    } catch (err: any) {
      console.error('[MYSQL MIGRATION ERROR]', err.message);
    }
  }

  private mapRowToVulnerability(row: any): VulnerabilityRecord {
    let references: string[] = [];
    try {
      references = JSON.parse(row.references_json || row.references || '[]');
    } catch {
      references = [];
    }

    return {
      id: row.id,
      cveId: row.cve_id,
      title: row.title,
      description: row.description,
      severity: row.severity,
      cvssScore: Number(row.cvss_score),
      cvssVector: row.cvss_vector || undefined,
      attackVector: row.attack_vector || undefined,
      attackComplexity: row.attack_complexity || undefined,
      privilegesRequired: row.privileges_required || undefined,
      userInteraction: row.user_interaction || undefined,
      affectedVendor: row.affected_vendor,
      affectedProduct: row.affected_product,
      affectedVersions: row.affected_versions || undefined,
      publishedDate: row.published_date,
      modifiedDate: row.modified_date,
      exploitAvailable: Boolean(row.exploit_available),
      knownExploited: Boolean(row.known_exploited),
      source: row.source,
      references,
      remediation: row.remediation || undefined,
      lastUpdated: row.last_updated,
      cyberGuardPriority: row.cyberguard_priority || 'MEDIUM',
      cyberGuardScore: Number(row.cyberguard_score || 50),
      confidence: Number(row.confidence || 80)
    };
  }

  public async upsertVulnerability(record: VulnerabilityRecord, sourceName: string): Promise<{ action: 'INSERT' | 'UPDATE' | 'SKIP' }> {
    if (!this.pool || !this.isConnected) return { action: 'SKIP' };

    const [rows]: any = await this.pool.query('SELECT * FROM vulnerabilities WHERE cve_id = ?', [record.cveId]);
    const existingRow = rows[0];

    if (!existingRow) {
      const risk = calculateCyberGuardRisk({
        cvssScore: record.cvssScore,
        knownExploited: record.knownExploited,
        exploitAvailable: record.exploitAvailable,
        attackVector: record.attackVector,
        attackComplexity: record.attackComplexity,
        privilegesRequired: record.privilegesRequired,
        userInteraction: record.userInteraction,
        publishedDate: record.publishedDate,
        modifiedDate: record.modifiedDate,
        source: record.source
      });

      const id = record.id || `vuln-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
      const refStr = JSON.stringify(record.references || []);

      await this.pool.query(
        `INSERT INTO vulnerabilities (
          id, cve_id, title, description, severity, cvss_score, cvss_vector,
          attack_vector, attack_complexity, privileges_required, user_interaction,
          affected_vendor, affected_product, affected_versions, published_date,
          modified_date, exploit_available, known_exploited, source, references_json, \`references\`,
          remediation, last_updated, cyberguard_priority, cyberguard_score, confidence
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          id,
          record.cveId,
          record.title || record.cveId,
          record.description || 'No description provided.',
          record.severity || 'UNKNOWN',
          record.cvssScore ?? 5.0,
          record.cvssVector || null,
          record.attackVector || null,
          record.attackComplexity || null,
          record.privilegesRequired || null,
          record.userInteraction || null,
          record.affectedVendor || 'Unknown Vendor',
          record.affectedProduct || 'Unknown Product',
          record.affectedVersions || null,
          record.publishedDate || new Date().toISOString(),
          record.modifiedDate || new Date().toISOString(),
          record.exploitAvailable ? 1 : 0,
          record.knownExploited ? 1 : 0,
          record.source || sourceName,
          refStr,
          refStr,
          record.remediation || null,
          new Date().toISOString(),
          risk.cyberGuardPriority,
          risk.cyberGuardScore,
          risk.confidence
        ]
      );

      await this.pool.query(
        `INSERT INTO affected_products (id, vulnerability_id, cve_id, vendor, product, versions)
         VALUES (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE vendor = VALUES(vendor), product = VALUES(product)`,
        [
          `aff-${id}`,
          id,
          record.cveId,
          record.affectedVendor || 'Unknown Vendor',
          record.affectedProduct || 'Unknown Product',
          record.affectedVersions || null
        ]
      );

      return { action: 'INSERT' };
    }

    const existing = this.mapRowToVulnerability(existingRow);
    let mergedSource = existing.source;
    if (!mergedSource.includes(sourceName) && sourceName && sourceName !== 'Demo Baseline') {
      mergedSource = `${mergedSource} + ${sourceName}`;
    }

    const refsSet = new Set([...existing.references, ...(record.references || [])]);
    const mergedReferences = Array.from(refsSet);
    const refStr = JSON.stringify(mergedReferences);

    const mergedKnownExploited = existing.knownExploited || record.knownExploited;
    const mergedExploitAvailable = existing.exploitAvailable || record.exploitAvailable;
    const mergedCvss = (record.cvssScore && record.cvssScore > 0) ? record.cvssScore : existing.cvssScore;
    const mergedSeverity = record.severity !== 'UNKNOWN' ? record.severity : existing.severity;

    const risk = calculateCyberGuardRisk({
      cvssScore: mergedCvss,
      knownExploited: mergedKnownExploited,
      exploitAvailable: mergedExploitAvailable,
      attackVector: record.attackVector || existing.attackVector,
      attackComplexity: record.attackComplexity || existing.attackComplexity,
      privilegesRequired: record.privilegesRequired || existing.privilegesRequired,
      userInteraction: record.userInteraction || existing.userInteraction,
      publishedDate: existing.publishedDate,
      modifiedDate: record.modifiedDate || existing.modifiedDate,
      source: mergedSource
    });

    await this.pool.query(
      `UPDATE vulnerabilities SET
        title = CASE WHEN ? != '' THEN ? ELSE title END,
        severity = ?,
        cvss_score = ?,
        affected_vendor = CASE WHEN ? != 'Unknown Vendor' THEN ? ELSE affected_vendor END,
        affected_product = CASE WHEN ? != 'Unknown Product' THEN ? ELSE affected_product END,
        modified_date = ?,
        exploit_available = ?,
        known_exploited = ?,
        source = ?,
        references_json = ?,
        \`references\` = ?,
        remediation = COALESCE(?, remediation),
        last_updated = ?,
        cyberguard_priority = ?,
        cyberguard_score = ?,
        confidence = ?
      WHERE cve_id = ?`,
      [
        record.title || '', record.title || '',
        mergedSeverity,
        mergedCvss,
        record.affectedVendor || 'Unknown Vendor', record.affectedVendor || 'Unknown Vendor',
        record.affectedProduct || 'Unknown Product', record.affectedProduct || 'Unknown Product',
        record.modifiedDate || existing.modifiedDate,
        mergedExploitAvailable ? 1 : 0,
        mergedKnownExploited ? 1 : 0,
        mergedSource,
        refStr,
        refStr,
        record.remediation || existing.remediation || null,
        new Date().toISOString(),
        risk.cyberGuardPriority,
        risk.cyberGuardScore,
        risk.confidence,
        record.cveId
      ]
    );

    return { action: 'UPDATE' };
  }

  public async bulkUpsertVulnerabilities(records: VulnerabilityRecord[], sourceName: string): Promise<{ added: number; updated: number; skipped: number }> {
    let added = 0;
    let updated = 0;
    let skipped = 0;

    for (const record of records) {
      try {
        const res = await this.upsertVulnerability(record, sourceName);
        if (res.action === 'INSERT') added++;
        else if (res.action === 'UPDATE') updated++;
        else skipped++;
      } catch (err) {
        skipped++;
      }
    }

    return { added, updated, skipped };
  }

  public async getVulnerabilities(options: VulnerabilityFilterOptions = {}): Promise<{
    data: VulnerabilityRecord[];
    pagination: { total: number; page: number; limit: number; totalPages: number };
  }> {
    if (!this.pool || !this.isConnected) {
      return { data: [], pagination: { total: 0, page: 1, limit: 20, totalPages: 1 } };
    }

    const {
      search,
      cveId,
      vendor,
      product,
      severity,
      minCvss,
      maxCvss,
      knownExploited,
      source,
      cyberGuardPriority,
      sortBy = 'cyberGuardScore',
      sortOrder = 'desc',
      page = 1,
      limit = 20
    } = options;

    const conditions: string[] = ['1=1'];
    const params: any[] = [];

    if (search && search.trim()) {
      const s = `%${search.trim()}%`;
      conditions.push(`(cve_id LIKE ? OR title LIKE ? OR description LIKE ? OR affected_vendor LIKE ? OR affected_product LIKE ?)`);
      params.push(s, s, s, s, s);
    }

    if (cveId && cveId.trim()) {
      conditions.push(`cve_id LIKE ?`);
      params.push(`%${cveId.trim()}%`);
    }

    if (vendor && vendor.trim()) {
      conditions.push(`affected_vendor LIKE ?`);
      params.push(`%${vendor.trim()}%`);
    }

    if (product && product.trim()) {
      conditions.push(`affected_product LIKE ?`);
      params.push(`%${product.trim()}%`);
    }

    if (severity && severity.trim() && severity !== 'ALL') {
      conditions.push(`severity = ?`);
      params.push(severity.toUpperCase());
    }

    if (cyberGuardPriority && cyberGuardPriority.trim() && cyberGuardPriority !== 'ALL') {
      conditions.push(`cyberguard_priority = ?`);
      params.push(cyberGuardPriority.toUpperCase());
    }

    if (typeof minCvss === 'number') {
      conditions.push(`cvss_score >= ?`);
      params.push(minCvss);
    }

    if (typeof maxCvss === 'number') {
      conditions.push(`cvss_score <= ?`);
      params.push(maxCvss);
    }

    if (typeof knownExploited === 'boolean') {
      conditions.push(`known_exploited = ?`);
      params.push(knownExploited ? 1 : 0);
    }

    if (source && source.trim() && source !== 'ALL') {
      conditions.push(`source LIKE ?`);
      params.push(`%${source.trim()}%`);
    }

    const whereClause = conditions.join(' AND ');

    const [countRows]: any = await this.pool.query(`SELECT COUNT(*) as total FROM vulnerabilities WHERE ${whereClause}`, params);
    const total = countRows[0] ? countRows[0].total : 0;

    const sortColMap: Record<string, string> = {
      cyberGuardScore: 'cyberguard_score',
      cvssScore: 'cvss_score',
      publishedDate: 'published_date',
      modifiedDate: 'modified_date',
      cveId: 'cve_id'
    };

    const sortColumn = sortColMap[sortBy] || 'cyberguard_score';
    const direction = sortOrder.toLowerCase() === 'asc' ? 'ASC' : 'DESC';

    const safeLimit = Math.max(1, Math.min(100, Number(limit) || 20));
    const safePage = Math.max(1, Number(page) || 1);
    const offset = (safePage - 1) * safeLimit;

    const [rows]: any = await this.pool.query(
      `SELECT * FROM vulnerabilities WHERE ${whereClause} ORDER BY ${sortColumn} ${direction} LIMIT ? OFFSET ?`,
      [...params, safeLimit, offset]
    );

    const data = rows.map((r: any) => this.mapRowToVulnerability(r));

    return {
      data,
      pagination: {
        total,
        page: safePage,
        limit: safeLimit,
        totalPages: Math.ceil(total / safeLimit) || 1
      }
    };
  }

  public async getVulnerabilityByCveId(cveId: string): Promise<VulnerabilityRecord | null> {
    if (!this.pool || !this.isConnected) return null;
    const [rows]: any = await this.pool.query('SELECT * FROM vulnerabilities WHERE cve_id = ? OR id = ?', [cveId, cveId]);
    return rows[0] ? this.mapRowToVulnerability(rows[0]) : null;
  }

  public async getRecentVulnerabilities(limit: number = 10): Promise<VulnerabilityRecord[]> {
    if (!this.pool || !this.isConnected) return [];
    const [rows]: any = await this.pool.query('SELECT * FROM vulnerabilities ORDER BY modified_date DESC, published_date DESC LIMIT ?', [limit]);
    return rows.map((r: any) => this.mapRowToVulnerability(r));
  }

  public async getTrendingVulnerabilities(limit: number = 10): Promise<VulnerabilityRecord[]> {
    if (!this.pool || !this.isConnected) return [];
    const [rows]: any = await this.pool.query('SELECT * FROM vulnerabilities ORDER BY cyberguard_score DESC, cvss_score DESC LIMIT ?', [limit]);
    return rows.map((r: any) => this.mapRowToVulnerability(r));
  }

  public async getExploitedVulnerabilities(limit: number = 20): Promise<VulnerabilityRecord[]> {
    if (!this.pool || !this.isConnected) return [];
    const [rows]: any = await this.pool.query('SELECT * FROM vulnerabilities WHERE known_exploited = 1 ORDER BY cyberguard_score DESC LIMIT ?', [limit]);
    return rows.map((r: any) => this.mapRowToVulnerability(r));
  }

  public async getVulnerabilityStats(): Promise<VulnerabilityStats> {
    if (!this.pool || !this.isConnected) {
      return {
        total: 0, critical: 0, high: 0, medium: 0, low: 0,
        knownExploited: 0, exploitAvailable: 0, avgCvssScore: 0, avgCyberGuardScore: 0,
        sourcesBreakdown: {}, topVendors: [], topProducts: [],
        lastSyncTime: null, lastSuccessfulSyncTime: null, syncState: 'DEMO_BASELINE'
      };
    }

    const [rows]: any = await this.pool.query(`
      SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
        SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high,
        SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
        SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low,
        SUM(CASE WHEN known_exploited = 1 THEN 1 ELSE 0 END) as knownExploited,
        SUM(CASE WHEN exploit_available = 1 THEN 1 ELSE 0 END) as exploitAvailable,
        AVG(cvss_score) as avgCvss,
        AVG(cyberguard_score) as avgCyberGuard
      FROM vulnerabilities
    `);
    const totalRow = rows[0] || {};

    const [sourcesRows]: any = await this.pool.query(`SELECT source, COUNT(*) as count FROM vulnerabilities GROUP BY source`);
    const sourcesBreakdown: Record<string, number> = {};
    for (const r of sourcesRows) {
      sourcesBreakdown[r.source] = r.count;
    }

    const [topVendors]: any = await this.pool.query(`
      SELECT affected_vendor as vendor, COUNT(*) as count 
      FROM vulnerabilities 
      WHERE affected_vendor != 'Unknown Vendor'
      GROUP BY affected_vendor 
      ORDER BY count DESC 
      LIMIT 6
    `);

    const [topProducts]: any = await this.pool.query(`
      SELECT affected_product as product, COUNT(*) as count 
      FROM vulnerabilities 
      WHERE affected_product != 'Unknown Product'
      GROUP BY affected_product 
      ORDER BY count DESC 
      LIMIT 6
    `);

    const [lastLogRows]: any = await this.pool.query('SELECT * FROM sync_logs ORDER BY created_at DESC LIMIT 1');
    const lastLog = lastLogRows[0];
    const [lastSuccessLogRows]: any = await this.pool.query("SELECT * FROM sync_logs WHERE status = 'SUCCESS' OR status = 'PARTIAL' ORDER BY created_at DESC LIMIT 1");
    const lastSuccessLog = lastSuccessLogRows[0];

    return {
      total: totalRow.total || 0,
      critical: Number(totalRow.critical || 0),
      high: Number(totalRow.high || 0),
      medium: Number(totalRow.medium || 0),
      low: Number(totalRow.low || 0),
      knownExploited: Number(totalRow.knownExploited || 0),
      exploitAvailable: Number(totalRow.exploitAvailable || 0),
      avgCvssScore: totalRow.avgCvss ? Number(Number(totalRow.avgCvss).toFixed(1)) : 0,
      avgCyberGuardScore: totalRow.avgCyberGuard ? Number(Number(totalRow.avgCyberGuard).toFixed(1)) : 0,
      sourcesBreakdown,
      topVendors,
      topProducts,
      lastSyncTime: lastLog ? lastLog.created_at : null,
      lastSuccessfulSyncTime: lastSuccessLog ? lastSuccessLog.created_at : null,
      syncState: lastSuccessLog ? 'LIVE' : 'DEMO_BASELINE'
    };
  }

  public async getSources(): Promise<VulnerabilitySource[]> {
    if (!this.pool || !this.isConnected) return [];
    const [rows]: any = await this.pool.query('SELECT * FROM vulnerability_sources');
    return rows.map((r: any) => ({
      id: r.id,
      name: r.name,
      type: r.type,
      url: r.url,
      enabled: Boolean(r.enabled),
      lastSyncAt: r.last_sync_at,
      syncStatus: r.sync_status,
      errorMessage: r.error_message,
      recordsCount: r.records_count
    }));
  }

  public async updateSourceStatus(type: string, status: 'IDLE' | 'SYNCING' | 'SUCCESS' | 'ERROR', errorMessage?: string | null) {
    if (!this.pool || !this.isConnected) return;
    await this.pool.query(
      `UPDATE vulnerability_sources SET sync_status = ?, error_message = ?, last_sync_at = ? WHERE type = ? OR id = ?`,
      [status, errorMessage || null, new Date().toISOString(), type, type]
    );
  }

  public async addSyncLog(log: Omit<SyncLog, 'id'>) {
    if (!this.pool || !this.isConnected) return;
    const id = `sync-log-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
    await this.pool.query(
      `INSERT INTO sync_logs (id, source_name, status, records_added, records_updated, records_skipped, error_count, error_details, duration_ms, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id,
        log.sourceName,
        log.status,
        log.recordsAdded,
        log.recordsUpdated,
        log.recordsSkipped,
        log.errorCount,
        log.errorDetails || null,
        log.durationMs,
        log.createdAt || new Date().toISOString()
      ]
    );
  }

  public async getRecentSyncLogs(limit: number = 10): Promise<SyncLog[]> {
    if (!this.pool || !this.isConnected) return [];
    const [rows]: any = await this.pool.query('SELECT * FROM sync_logs ORDER BY created_at DESC LIMIT ?', [limit]);
    return rows.map((r: any) => ({
      id: r.id,
      sourceName: r.source_name,
      status: r.status,
      recordsAdded: r.records_added,
      recordsUpdated: r.records_updated,
      recordsSkipped: r.records_skipped,
      errorCount: r.error_count,
      errorDetails: r.error_details,
      durationMs: r.duration_ms,
      createdAt: r.created_at
    }));
  }
}

export const mySqlDb = new MySqlVulnerabilityDatabase();
