import { SourceAdapter, AdapterFetchOptions, AdapterFetchResult } from './SourceAdapter.js';
import { VulnerabilityRecord, VulnerabilitySeverity } from '../../types/vulnerability.js';
import { calculateCyberGuardRisk } from '../riskPrioritization.js';

export class OSVAdapter extends SourceAdapter {
  public readonly name = 'Open Source Vulnerabilities (OSV.dev)';
  public readonly type = 'OSV';
  public readonly defaultUrl = 'https://api.osv.dev/v1/query';

  public async fetchRecords(options: AdapterFetchOptions = {}): Promise<AdapterFetchResult> {
    const startTime = Date.now();
    const records: VulnerabilityRecord[] = [];

    try {
      console.log(`[${this.name}] Querying OSV / Open Source Vulnerability feeds...`);

      // Query prominent ecosystem packages for recent advisories
      const targets = [
        { package: { name: 'express', ecosystem: 'npm' } },
        { package: { name: 'axios', ecosystem: 'npm' } },
        { package: { name: 'lodash', ecosystem: 'npm' } },
        { package: { name: 'django', ecosystem: 'PyPI' } },
        { package: { name: 'flask', ecosystem: 'PyPI' } },
        { package: { name: 'openssl', ecosystem: 'OSS-Fuzz' } },
        { package: { name: 'jsonwebtoken', ecosystem: 'npm' } }
      ];

      for (const target of targets) {
        try {
          const response = await this.fetchWithRetry(this.defaultUrl, {
            method: 'POST',
            body: JSON.stringify(target)
          }, 1);

          const data = await response.json();
          if (!data || !Array.isArray(data.vulns)) continue;

          for (const vuln of data.vulns) {
            // Find CVE alias if available
            const cveAlias = (vuln.aliases || []).find((a: string) => a.startsWith('CVE-')) || vuln.id;
            if (!cveAlias) continue;

            const severityScore = vuln.database_specific?.cvss_score || vuln.severity?.[0]?.score || 7.5;
            const cvssNum = typeof severityScore === 'number' ? severityScore : parseFloat(severityScore) || 7.5;

            let severity: VulnerabilitySeverity = 'HIGH';
            if (cvssNum >= 9.0) severity = 'CRITICAL';
            else if (cvssNum >= 7.0) severity = 'HIGH';
            else if (cvssNum >= 4.0) severity = 'MEDIUM';
            else severity = 'LOW';

            const vendor = target.package.ecosystem || 'Open Source Package';
            const product = target.package.name;

            const pubDate = vuln.published || new Date().toISOString();
            const modDate = vuln.modified || pubDate;

            const references: string[] = (vuln.references || []).map((r: any) => r.url).filter(Boolean).slice(0, 4);

            const risk = calculateCyberGuardRisk({
              cvssScore: cvssNum,
              knownExploited: false,
              exploitAvailable: false,
              attackVector: 'NETWORK',
              attackComplexity: 'LOW',
              privilegesRequired: 'NONE',
              publishedDate: pubDate,
              modifiedDate: modDate,
              source: 'OSV'
            });

            records.push({
              id: `osv-${vuln.id}`,
              cveId: cveAlias,
              title: vuln.summary || `${product} (${vendor}) Security Advisory`,
              description: vuln.details || vuln.summary || 'Security advisory identified in open-source package ecosystem.',
              severity,
              cvssScore: cvssNum,
              attackVector: 'NETWORK',
              attackComplexity: 'LOW',
              privilegesRequired: 'NONE',
              userInteraction: 'NONE',
              affectedVendor: vendor,
              affectedProduct: product,
              affectedVersions: vuln.affected?.[0]?.ranges?.[0]?.events?.[0]?.introduced || undefined,
              publishedDate: pubDate,
              modifiedDate: modDate,
              exploitAvailable: false,
              knownExploited: false,
              source: 'OSV',
              references,
              remediation: `Upgrade ${product} package to the latest patched release.`,
              lastUpdated: new Date().toISOString(),
              cyberGuardPriority: risk.cyberGuardPriority,
              cyberGuardScore: risk.cyberGuardScore,
              confidence: 88
            });
          }
        } catch {
          // continue with other packages
        }
      }

      const durationMs = Date.now() - startTime;
      console.log(`[${this.name}] Successfully normalized ${records.length} OSV vulnerability items in ${durationMs}ms`);

      return {
        sourceName: this.name,
        records,
        durationMs,
        success: true
      };
    } catch (err: any) {
      const durationMs = Date.now() - startTime;
      console.error(`[${this.name}] OSV feed error:`, err.message);
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
