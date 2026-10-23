import { SourceAdapter, AdapterFetchOptions, AdapterFetchResult } from './SourceAdapter.js';
import { VulnerabilityRecord, VulnerabilitySeverity } from '../../types/vulnerability.js';
import { calculateCyberGuardRisk } from '../riskPrioritization.js';

export class GitHubAdvisoryAdapter extends SourceAdapter {
  public readonly name = 'GitHub Security Advisories';
  public readonly type = 'GITHUB_ADVISORY';
  public readonly defaultUrl = 'https://api.github.com/advisories';

  public async fetchRecords(options: AdapterFetchOptions = {}): Promise<AdapterFetchResult> {
    const startTime = Date.now();
    const records: VulnerabilityRecord[] = [];

    try {
      console.log(`[${this.name}] Querying GitHub Security Advisory API...`);
      const limit = options.limit || 30;
      const url = new URL(this.defaultUrl);
      url.searchParams.set('per_page', String(limit));
      url.searchParams.set('type', 'reviewed');

      const headers: Record<string, string> = {
        Accept: 'application/vnd.github+json'
      };

      if (process.env.GITHUB_TOKEN) {
        headers['Authorization'] = `Bearer ${process.env.GITHUB_TOKEN}`;
      }

      const response = await this.fetchWithRetry(url.toString(), { headers });
      const data = await response.json();

      if (!Array.isArray(data)) {
        throw new Error('Invalid GitHub advisory response format');
      }

      for (const item of data) {
        const cveId = item.cve_id || item.ghsa_id;
        if (!cveId) continue;

        const rawSev = (item.severity || 'medium').toUpperCase();
        let severity: VulnerabilitySeverity = 'MEDIUM';
        if (rawSev === 'CRITICAL') severity = 'CRITICAL';
        else if (rawSev === 'HIGH') severity = 'HIGH';
        else if (rawSev === 'LOW') severity = 'LOW';

        const cvssScore = item.cvss?.score || (severity === 'CRITICAL' ? 9.2 : severity === 'HIGH' ? 7.8 : 5.5);
        const cvssVector = item.cvss?.vector_string || undefined;

        const affected = item.vulnerabilities?.[0];
        const vendor = affected?.package?.ecosystem || 'GitHub Ecosystem';
        const product = affected?.package?.name || 'Open Source Project';
        const versions = affected?.vulnerable_version_range || undefined;

        const pubDate = item.published_at || new Date().toISOString();
        const modDate = item.updated_at || pubDate;

        const references: string[] = (item.references || []).map((r: any) => (typeof r === 'string' ? r : r.url)).filter(Boolean).slice(0, 4);
        if (item.html_url && !references.includes(item.html_url)) {
          references.unshift(item.html_url);
        }

        const risk = calculateCyberGuardRisk({
          cvssScore,
          knownExploited: false,
          exploitAvailable: severity === 'CRITICAL',
          attackVector: 'NETWORK',
          attackComplexity: 'LOW',
          privilegesRequired: 'NONE',
          publishedDate: pubDate,
          modifiedDate: modDate,
          source: 'GitHub Advisory'
        });

        records.push({
          id: `ghsa-${item.ghsa_id || item.cve_id}`,
          cveId,
          title: item.summary || `${product} Security Advisory (${cveId})`,
          description: item.description ? item.description.slice(0, 600) : 'Security vulnerability documented in GitHub Advisory Database.',
          severity,
          cvssScore,
          cvssVector,
          attackVector: 'NETWORK',
          attackComplexity: 'LOW',
          privilegesRequired: 'NONE',
          userInteraction: 'NONE',
          affectedVendor: vendor,
          affectedProduct: product,
          affectedVersions: versions,
          publishedDate: pubDate,
          modifiedDate: modDate,
          exploitAvailable: severity === 'CRITICAL',
          knownExploited: false,
          source: 'GitHub Advisory',
          references,
          remediation: affected?.first_patched_version 
            ? `Upgrade ${product} to version ${affected.first_patched_version} or higher.`
            : 'Upgrade affected repository dependencies to latest patched releases.',
          lastUpdated: new Date().toISOString(),
          cyberGuardPriority: risk.cyberGuardPriority,
          cyberGuardScore: risk.cyberGuardScore,
          confidence: 90
        });
      }

      const durationMs = Date.now() - startTime;
      console.log(`[${this.name}] Successfully normalized ${records.length} GitHub advisories in ${durationMs}ms`);

      return {
        sourceName: this.name,
        records,
        durationMs,
        success: true
      };
    } catch (err: any) {
      const durationMs = Date.now() - startTime;
      console.error(`[${this.name}] Failed to fetch GitHub advisories:`, err.message);
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
