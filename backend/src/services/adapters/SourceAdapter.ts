import { VulnerabilityRecord } from '../../types/vulnerability.js';

export interface AdapterFetchOptions {
  since?: string;
  limit?: number;
  apiKey?: string;
}

export interface AdapterFetchResult {
  sourceName: string;
  records: VulnerabilityRecord[];
  durationMs: number;
  success: boolean;
  errorMessage?: string;
}

export abstract class SourceAdapter {
  public abstract readonly name: string;
  public abstract readonly type: string;
  public abstract readonly defaultUrl: string;

  protected timeoutMs: number = 12000;
  protected maxRetries: number = 2;

  /**
   * Safe fetch with configurable timeout, headers, and retry backoff.
   */
  protected async fetchWithRetry(url: string, options: RequestInit = {}, retries: number = this.maxRetries): Promise<Response> {
    let lastError: any = null;

    for (let attempt = 1; attempt <= retries; attempt++) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

      try {
        const response = await fetch(url, {
          ...options,
          signal: controller.signal,
          headers: {
            'User-Agent': 'CyberGuard-Grid-ThreatIntelligence/1.0',
            Accept: 'application/json',
            ...(options.headers || {})
          }
        });

        clearTimeout(timeoutId);

        if (response.status === 429) {
          // Rate limited: wait longer before retrying
          console.warn(`[${this.name}] Rate limited (429). Backing off...`);
          if (attempt < retries) {
            await new Promise((r) => setTimeout(r, 2000 * attempt));
            continue;
          }
        }

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        return response;
      } catch (err: any) {
        clearTimeout(timeoutId);
        lastError = err;
        const isAbort = err.name === 'AbortError' || err.message?.includes('aborted');
        console.warn(`[${this.name}] Attempt ${attempt}/${retries} failed: ${isAbort ? 'Request timed out' : err.message}`);

        if (attempt < retries) {
          await new Promise((r) => setTimeout(r, 1000 * attempt));
        }
      }
    }

    throw lastError || new Error(`Failed to fetch from ${this.name} after ${retries} attempts`);
  }

  /**
   * Main adapter ingestion method. Must return normalized VulnerabilityRecord items.
   */
  public abstract fetchRecords(options?: AdapterFetchOptions): Promise<AdapterFetchResult>;
}
