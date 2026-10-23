import { SourceAdapter } from './adapters/SourceAdapter.js';
import { CISAKEVAdapter } from './adapters/CISAKEVAdapter.js';
import { NVDAdapter } from './adapters/NVDAdapter.js';
import { OSVAdapter } from './adapters/OSVAdapter.js';
import { GitHubAdvisoryAdapter } from './adapters/GitHubAdvisoryAdapter.js';
import { vulnerabilityDb } from '../db/vulnerabilityDb.js';
import { SyncEngineStatus } from '../types/vulnerability.js';

export class SyncService {
  private adapters: SourceAdapter[] = [];
  private isSyncing: boolean = false;
  private syncTimer: NodeJS.Timeout | null = null;
  private intervalMinutes: number = 30;

  private lastSyncTime: string | null = null;
  private lastSuccessfulSyncTime: string | null = null;
  private lastSyncStats = {
    recordsAdded: 0,
    recordsUpdated: 0,
    recordsSkipped: 0,
    errors: 0
  };

  constructor() {
    // Register all authoritative source adapters
    this.adapters = [
      new CISAKEVAdapter(),
      new NVDAdapter(),
      new OSVAdapter(),
      new GitHubAdvisoryAdapter()
    ];
  }

  /**
   * Initializes automatic background sync scheduler.
   */
  public startScheduler(intervalMinutes: number = 30) {
    this.intervalMinutes = intervalMinutes;
    if (this.syncTimer) {
      clearInterval(this.syncTimer);
    }

    // Schedule recurring sync
    this.syncTimer = setInterval(() => {
      console.log('⏰ [CYBERGUARD SYNC] Triggering scheduled vulnerability synchronization...');
      this.runSync().catch((err) => {
        console.error('Scheduled sync error:', err);
      });
    }, this.intervalMinutes * 60 * 1000);

    // Run an initial non-blocking background sync after 5 seconds
    setTimeout(() => {
      this.runSync().catch((err) => {
        console.warn('Initial background sync note:', err.message);
      });
    }, 5000);

    console.log(`📡 [CYBERGUARD SYNC] Automatic intelligence scheduler active (${this.intervalMinutes}m interval)`);
  }

  public stopScheduler() {
    if (this.syncTimer) {
      clearInterval(this.syncTimer);
      this.syncTimer = null;
    }
  }

  /**
   * Executes a complete synchronization pass across all configured sources.
   * Partial failures are isolated so that one failing API never interrupts others.
   */
  public async runSync(options: { force?: boolean } = {}): Promise<SyncEngineStatus> {
    if (this.isSyncing) {
      console.log('[CYBERGUARD SYNC] Sync is already in progress, returning current status.');
      return this.getStatus();
    }

    this.isSyncing = true;
    this.lastSyncTime = new Date().toISOString();

    let totalAdded = 0;
    let totalUpdated = 0;
    let totalSkipped = 0;
    let errorCount = 0;
    const errorDetailsList: string[] = [];

    console.log('🔄 [CYBERGUARD SYNC] Starting live vulnerability synchronization cycle...');

    for (const adapter of this.adapters) {
      const sourceStartTime = Date.now();
      vulnerabilityDb.updateSourceStatus(adapter.type, 'SYNCING');

      try {
        const result = await adapter.fetchRecords();

        if (result.success && result.records.length > 0) {
          const upsertResult = vulnerabilityDb.bulkUpsertVulnerabilities(result.records, adapter.name);
          totalAdded += upsertResult.added;
          totalUpdated += upsertResult.updated;
          totalSkipped += upsertResult.skipped;

          vulnerabilityDb.updateSourceStatus(adapter.type, 'SUCCESS');
          vulnerabilityDb.addSyncLog({
            sourceName: adapter.name,
            status: 'SUCCESS',
            recordsAdded: upsertResult.added,
            recordsUpdated: upsertResult.updated,
            recordsSkipped: upsertResult.skipped,
            errorCount: 0,
            durationMs: Date.now() - sourceStartTime,
            createdAt: new Date().toISOString()
          });
        } else if (result.success && result.records.length === 0) {
          vulnerabilityDb.updateSourceStatus(adapter.type, 'SUCCESS');
          vulnerabilityDb.addSyncLog({
            sourceName: adapter.name,
            status: 'SUCCESS',
            recordsAdded: 0,
            recordsUpdated: 0,
            recordsSkipped: 0,
            errorCount: 0,
            durationMs: Date.now() - sourceStartTime,
            createdAt: new Date().toISOString()
          });
        } else {
          errorCount++;
          errorDetailsList.push(`${adapter.name}: ${result.errorMessage}`);
          vulnerabilityDb.updateSourceStatus(adapter.type, 'ERROR', result.errorMessage);
          vulnerabilityDb.addSyncLog({
            sourceName: adapter.name,
            status: 'FAILED',
            recordsAdded: 0,
            recordsUpdated: 0,
            recordsSkipped: 0,
            errorCount: 1,
            errorDetails: result.errorMessage,
            durationMs: Date.now() - sourceStartTime,
            createdAt: new Date().toISOString()
          });
        }
      } catch (err: any) {
        errorCount++;
        errorDetailsList.push(`${adapter.name}: ${err.message}`);
        vulnerabilityDb.updateSourceStatus(adapter.type, 'ERROR', err.message);
        vulnerabilityDb.addSyncLog({
          sourceName: adapter.name,
          status: 'FAILED',
          recordsAdded: 0,
          recordsUpdated: 0,
          recordsSkipped: 0,
          errorCount: 1,
          errorDetails: err.message,
          durationMs: Date.now() - sourceStartTime,
          createdAt: new Date().toISOString()
        });
      }
    }

    this.lastSyncStats = {
      recordsAdded: totalAdded,
      recordsUpdated: totalUpdated,
      recordsSkipped: totalSkipped,
      errors: errorCount
    };

    if (errorCount === 0 || totalAdded > 0 || totalUpdated > 0) {
      this.lastSuccessfulSyncTime = new Date().toISOString();
    }

    this.isSyncing = false;
    console.log(`✅ [CYBERGUARD SYNC] Sync completed: +${totalAdded} new, ~${totalUpdated} updated, -${totalSkipped} skipped, ${errorCount} errors.`);

    return this.getStatus();
  }

  public async getStatus(): Promise<SyncEngineStatus> {
    const sources = await vulnerabilityDb.getSources();
    const recentLogs = await vulnerabilityDb.getRecentSyncLogs(6);

    let status: 'IDLE' | 'SYNCING' | 'SUCCESS' | 'ERROR' = 'IDLE';
    if (this.isSyncing) status = 'SYNCING';
    else if (this.lastSyncStats.errors > 0 && this.lastSyncStats.recordsAdded === 0 && this.lastSyncStats.recordsUpdated === 0) status = 'ERROR';
    else if (this.lastSuccessfulSyncTime) status = 'SUCCESS';

    return {
      status,
      lastSyncTime: this.lastSyncTime,
      lastSuccessfulSyncTime: this.lastSuccessfulSyncTime,
      recordsAdded: this.lastSyncStats.recordsAdded,
      recordsUpdated: this.lastSyncStats.recordsUpdated,
      recordsSkipped: this.lastSyncStats.recordsSkipped,
      errors: this.lastSyncStats.errors,
      activeSources: this.adapters.map((a) => a.name),
      sources,
      recentLogs,
      isLive: Boolean(this.lastSuccessfulSyncTime)
    };
  }
}

export const syncService = new SyncService();
