import { SourceAdapter, AdapterFetchOptions, AdapterFetchResult } from './SourceAdapter.js';
import { VulnerabilityRecord } from '../../types/vulnerability.js';
import { calculateCyberGuardRisk } from '../riskPrioritization.js';

export class CISAKEVAdapter extends SourceAdapter {
  public readonly name = 'CISA Known Exploited Vulnerabilities (KEV)';
  public readonly type = 'CISA_KEV';
  public readonly defaultUrl = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

  public async fetchRecords(options: AdapterFetchOptions = {}): Promise<AdapterFetchResult> {
    const startTime = Date.now();
    const records: VulnerabilityRecord[] = [];

    try {
      console.log(`[${this.name}] Ingesting official CISA KEV catalog...`);
      const response = await this.fetchWithRetry(this.defaultUrl);
      const data = await response.json();

      if (!data || !Array.isArray(data.vulnerabilities)) {
        throw new Error('Invalid CISA KEV JSON structure');
      }

      // Process recent / subset or full list depending on options
      const rawList = data.vulnerabilities;
      // Sort newest dateAdded first
      rawList.sort((a: any, b: any) => new Date(b.dateAdded || 0).getTime() - new Date(a.dateAdded || 0).getTime());

      const limit = options.limit || 150; // Ingest top 150 active / most recent KEVs per sync
      const selected = rawList.slice(0, limit);

      for (const item of selected) {
        if (!item.cveID) continue;

        const remediation = item.requiredAction 
          ? `[CISA Directive - Due: ${item.dueDate || 'Immediate'}] ${item.requiredAction} ${item.notes || ''}`.trim()
          : item.notes || 'Apply vendor patches immediately.';

        const pubDate = item.dateAdded ? `${item.dateAdded}T00:00:00Z` : new Date().toISOString();

        // CISA KEV vulnerabilities are actively weaponized: baseline CVSS 9.0+ if unspecified
        const cvssScore = 9.0;
        const risk = calculateCyberGuardRisk({
          cvssScore,
          knownExploited: true,
          exploitAvailable: true,
          attackVector: 'NETWORK',
          attackComplexity: 'LOW',
          privilegesRequired: 'NONE',
          publishedDate: pubDate,
          modifiedDate: pubDate,
          source: 'CISA KEV'
        });

        records.push({
          id: `cisa-${item.cveID}`,
          cveId: item.cveID,
          title: item.vulnerabilityName || `${item.vendorProject || ''} ${item.product || ''} Vulnerability`.trim(),
          description: item.shortDescription || 'Confirmed weaponized vulnerability listed in CISA Known Exploited Catalog.',
          severity: 'CRITICAL',
          cvssScore,
          attackVector: 'NETWORK',
          attackComplexity: 'LOW',
          privilegesRequired: 'NONE',
          userInteraction: 'NONE',
          affectedVendor: item.vendorProject || 'Unknown Vendor',
          affectedProduct: item.product || 'Unknown Product',
          publishedDate: pubDate,
          modifiedDate: pubDate,
          exploitAvailable: true,
          knownExploited: true,
          source: 'CISA KEV',
          references: [
            `https://nvd.nist.gov/vuln/detail/${item.cveID}`,
            'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'
          ],
          remediation,
          lastUpdated: new Date().toISOString(),
          cyberGuardPriority: risk.cyberGuardPriority,
          cyberGuardScore: risk.cyberGuardScore,
          confidence: 96
        });
      }

      const durationMs = Date.now() - startTime;
      console.log(`[${this.name}] Successfully normalized ${records.length} CISA KEV records in ${durationMs}ms`);

      return {
        sourceName: this.name,
        records,
        durationMs,
        success: true
      };
    } catch (err: any) {
      const durationMs = Date.now() - startTime;
      console.error(`[${this.name}] Failed to fetch CISA KEV data:`, err.message);
      return {
        sourceName: this.name,
        records: [],
        durationMs,
        success: false,
        errorMessage: err.message
      };
    }
  }
}
