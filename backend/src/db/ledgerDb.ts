import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { LedgerRecord } from '../types.js';

export function computeSha256(data: string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

export function computeBlockHash(
  blockNumber: number,
  threatId: string,
  reporterOrg: string,
  patternHash: string,
  validators: string[],
  timestamp: string,
  previousHash: string
): string {
  const validatorStr = Array.isArray(validators) ? validators.join(',') : String(validators);
  const payload = `${blockNumber}${threatId}${reporterOrg}${patternHash}${validatorStr}${timestamp}${previousHash}`;
  return computeSha256(payload);
}

class LedgerDatabase {
  private db!: Database.Database;
  private dbPath: string;

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
    this.dbPath = path.join(dataDir, 'cyberguard_vulnerabilities.db');
    this.init();
  }

  private init() {
    this.db = new Database(this.dbPath);
    this.db.pragma('journal_mode = WAL');
    this.createTable();
    this.seedBaselineIfEmpty();
  }

  private createTable() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS dlt_blocks (
        block_number INTEGER PRIMARY KEY,
        threat_id TEXT NOT NULL,
        reporter_org TEXT NOT NULL,
        validators_json TEXT NOT NULL,
        status TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        pattern_hash TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        block_hash TEXT NOT NULL
      );
    `);
  }

  public getBaselineBlocks(): LedgerRecord[] {
    const genesisPrevHash = '0000000000000000000000000000000000000000000000000000000000000000';

    // Block 10419
    const b1Validators = ['Insurance Group', 'Demo Bank'];
    const b1Hash = computeBlockHash(
      10419,
      'TH-3901',
      'Insurance Group',
      '7c9e3b1a2d5f8e0c4b6a9d1e3f5a7b9c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a',
      b1Validators,
      '2026-09-04 07:12:00',
      genesisPrevHash
    );

    // Block 10420
    const b2Validators = ['FinTech Corp', 'Demo Bank', 'State University'];
    const b2Hash = computeBlockHash(
      10420,
      'TH-4019',
      'FinTech Corp',
      'e7c2d1b09876543210fedcba9876543210fedcba9876543210fedcba98765432',
      b2Validators,
      '2026-09-04 08:30:15',
      b1Hash
    );

    // Block 10421
    const b3Validators = ['Demo Bank', 'City Hospital', 'State University'];
    const b3Hash = computeBlockHash(
      10421,
      'TH-7821',
      'Demo Bank',
      'a8f3b29c91d4e5f670123456789abcdef0123456789abcdef0123456789ab2bd',
      b3Validators,
      '2026-09-04 09:45:10',
      b2Hash
    );

    return [
      {
        blockNumber: 10419,
        threatId: 'TH-3901',
        reporterOrg: 'Insurance Group',
        validators: b1Validators,
        status: 'CONFIRMED',
        timestamp: '2026-09-04 07:12:00',
        patternHash: '7c9e3b1a2d5f8e0c4b6a9d1e3f5a7b9c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a',
        previousHash: genesisPrevHash,
        blockHash: b1Hash
      },
      {
        blockNumber: 10420,
        threatId: 'TH-4019',
        reporterOrg: 'FinTech Corp',
        validators: b2Validators,
        status: 'CONFIRMED',
        timestamp: '2026-09-04 08:30:15',
        patternHash: 'e7c2d1b09876543210fedcba9876543210fedcba9876543210fedcba98765432',
        previousHash: b1Hash,
        blockHash: b2Hash
      },
      {
        blockNumber: 10421,
        threatId: 'TH-7821',
        reporterOrg: 'Demo Bank',
        validators: b3Validators,
        status: 'CONFIRMED',
        timestamp: '2026-09-04 09:45:10',
        patternHash: 'a8f3b29c91d4e5f670123456789abcdef0123456789abcdef0123456789ab2bd',
        previousHash: b2Hash,
        blockHash: b3Hash
      }
    ];
  }

  public seedBaselineIfEmpty() {
    const row = this.db.prepare('SELECT COUNT(*) as count FROM dlt_blocks').get() as { count: number };
    if (!row || row.count === 0) {
      this.resetToBaseline();
    }
  }

  public resetToBaseline(): LedgerRecord[] {
    const baseline = this.getBaselineBlocks();
    const deleteStmt = this.db.prepare('DELETE FROM dlt_blocks');
    const insertStmt = this.db.prepare(`
      INSERT INTO dlt_blocks (block_number, threat_id, reporter_org, validators_json, status, timestamp, pattern_hash, previous_hash, block_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const transaction = this.db.transaction((blocks: LedgerRecord[]) => {
      deleteStmt.run();
      for (const b of blocks) {
        insertStmt.run(
          b.blockNumber,
          b.threatId,
          b.reporterOrg,
          JSON.stringify(b.validators),
          b.status,
          b.timestamp,
          b.patternHash,
          b.previousHash,
          b.blockHash
        );
      }
    });

    transaction(baseline);
    return baseline;
  }

  public getAllBlocks(): LedgerRecord[] {
    const rows = this.db.prepare('SELECT * FROM dlt_blocks ORDER BY block_number ASC').all() as any[];
    return rows.map((r) => ({
      blockNumber: r.block_number,
      threatId: r.threat_id,
      reporterOrg: r.reporter_org,
      validators: JSON.parse(r.validators_json || '[]'),
      status: r.status,
      timestamp: r.timestamp,
      patternHash: r.pattern_hash,
      previousHash: r.previous_hash,
      blockHash: r.block_hash
    }));
  }

  public insertBlock(block: LedgerRecord): void {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO dlt_blocks (block_number, threat_id, reporter_org, validators_json, status, timestamp, pattern_hash, previous_hash, block_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      block.blockNumber,
      block.threatId,
      block.reporterOrg,
      JSON.stringify(block.validators),
      block.status,
      block.timestamp,
      block.patternHash,
      block.previousHash,
      block.blockHash
    );
  }

  public updateBlock(block: LedgerRecord): void {
    const stmt = this.db.prepare(`
      UPDATE dlt_blocks
      SET threat_id = ?, reporter_org = ?, validators_json = ?, status = ?, timestamp = ?, pattern_hash = ?, previous_hash = ?, block_hash = ?
      WHERE block_number = ?
    `);
    stmt.run(
      block.threatId,
      block.reporterOrg,
      JSON.stringify(block.validators),
      block.status,
      block.timestamp,
      block.patternHash,
      block.previousHash,
      block.blockHash,
      block.blockNumber
    );
  }

  public tamperBlock(blockNumber: number, newThreatId?: string, newPatternHash?: string): LedgerRecord | null {
    const blocks = this.getAllBlocks();
    const target = blocks.find((b) => b.blockNumber === blockNumber);
    if (!target) return null;

    target.threatId = newThreatId || `${target.threatId}-MALICIOUS-ALTERED`;
    if (newPatternHash) {
      target.patternHash = newPatternHash;
    }
    // Deliberately DO NOT update target.blockHash so the cryptographic signature is broken!
    this.updateBlock(target);
    return target;
  }
}

export const ledgerDb = new LedgerDatabase();
