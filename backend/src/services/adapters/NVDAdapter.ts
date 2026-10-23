import { SourceAdapter, AdapterFetchOptions, AdapterFetchResult } from './SourceAdapter.js';
import { VulnerabilityRecord, VulnerabilitySeverity } from '../../types/vulnerability.js';
import { calculateCyberGuardRisk } from '../riskPrioritization.js';

export class NVDAdapter extends SourceAdapter {
  public readonly name = 'NIST National Vulnerability Database (NVD 2.0)';
  public readonly type = 'NVD';
  public readonly defaultUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

  public async fetchRecords(options: AdapterFetchOptions = {}): Promise<AdapterFetchResult> {
    const startTime = Date.now();
    const records: VulnerabilityRecord[] = [];

    try {
      const limit = options.limit || 50;
      // Fetch recent critical/high CVEs or recent publications
      const url = new URL(this.defaultUrl);
      url.searchParams.set('resultsPerPage', String(limit));

      // Optional API Key header if provided in env
      const headers: Record<string, string> = {};
      const nvdApiKey = process.env.NVD_API_KEY || options.apiKey;
      if (nvdApiKey) {
        headers['apiKey'] = nvdApiKey;
      }

      console.log(`[${this.name}] Querying NIST NVD 2.0 API...`);
      const response = await this.fetchWithRetry(url.toString(), { headers });
      const data = await response.json();

      if (!data || !Array.isArray(data.vulnerabilities)) {
        throw new Error('Invalid NVD API response structure');
      }

      for (const item of data.vulnerabilities) {
        const cve = item.cve;
        if (!cve || !cve.id) continue;

        // Extract English description
        const descObj = (cve.descriptions || []).find((d: any) => d.lang === 'en') || cve.descriptions?.[0];
        const description = descObj?.value || 'No English description available in NVD.';

        // Extract CVSS v3.1 / v3.0 or v2 metrics
        let cvssScore = 5.0;
        let cvssVector = '';
        let severity: VulnerabilitySeverity = 'MEDIUM';
        let attackVector = 'NETWORK';
        let attackComplexity = 'LOW';
        let privilegesRequired = 'NONE';
        let userInteraction = 'NONE';

        const metricsV31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
        const metricsV30 = cve.metrics?.cvssMetricV30?.[0]?.cvssData;
        const metricsV2 = cve.metrics?.cvssMetricV2?.[0]?.cvssData;

        const cvssData = metricsV31 || metricsV30;
        if (cvssData) {
          cvssScore = Number(cvssData.baseScore) || 5.0;
          cvssVector = cvssData.vectorString || '';
          severity = (cvssData.baseSeverity || 'MEDIUM').toUpperCase() as VulnerabilitySeverity;
          attackVector = cvssData.attackVector || 'NETWORK';
          attackComplexity = cvssData.attackComplexity || 'LOW';
          privilegesRequired = cvssData.privilegesRequired || 'NONE';
          userInteraction = cvssData.userInteraction || 'NONE';
        } else if (metricsV2) {
          cvssScore = Number(metricsV2.baseScore) || 5.0;
          cvssVector = metricsV2.vectorString || '';
          severity = cvssScore >= 7.0 ? 'HIGH' : cvssScore >= 4.0 ? 'MEDIUM' : 'LOW';
          attackVector = metricsV2.accessVector || 'NETWORK';
          attackComplexity = metricsV2.accessComplexity || 'LOW';
        }

        // Extract affected vendor & product from configurations/CPEs if available
        let affectedVendor = 'Software Vendor';
        let affectedProduct = 'Target Product';
        let affectedVersions = '';

        try {
          const nodes = cve.configurations?.[0]?.nodes || [];
          for (const node of nodes) {
            const cpeMatch = node.cpeMatch?.[0];
            if (cpeMatch && cpeMatch.criteria) {
              // cpe:2.3:a:vendor:product:version:...
              const parts = cpeMatch.criteria.split(':');
              if (parts.length >= 5) {
                affectedVendor = parts[3].replace(/_/g, ' ');
                affectedProduct = parts[4].replace(/_/g, ' ');
                if (parts[5] && parts[5] !== '*') {
                  affectedVersions = parts[5];
                }
              }
              break;
            }
          }
        } catch {
          // fallback
        }

        // Extract references
        const references: string[] = (cve.references || []).map((r: any) => r.url).filter(Boolean).slice(0, 5);

        const publishedDate = cve.published || new Date().toISOString();
        const modifiedDate = cve.lastModified || publishedDate;

        const risk = calculateCyberGuardRisk({
          cvssScore,
          knownExploited: false,
          exploitAvailable: severity === 'CRITICAL',
          attackVector,
          attackComplexity,
          privilegesRequired,
          userInteraction,
          publishedDate,
          modifiedDate,
          source: 'NVD'
        });

        records.push({
          id: `nvd-${cve.id}`,
          cveId: cve.id,
          title: `${affectedVendor.toUpperCase()} ${affectedProduct} Vulnerability (${cve.id})`,
          description,
          severity,
          cvssScore,
          cvssVector,
          attackVector,
          attackComplexity,
          privilegesRequired,
          userInteraction,
          affectedVendor,
          affectedProduct,
          affectedVersions: affectedVersions || undefined,
          publishedDate,
          modifiedDate,
          exploitAvailable: severity === 'CRITICAL',
          knownExploited: false,
          source: 'NVD',
          references,
          remediation: 'Review official vendor security bulletin and apply available firmware/software updates.',
          lastUpdated: new Date().toISOString(),
          cyberGuardPriority: risk.cyberGuardPriority,
          cyberGuardScore: risk.cyberGuardScore,
          confidence: 92
        });
      }

      const durationMs = Date.now() - startTime;
      console.log(`[${this.name}] Successfully normalized ${records.length} NVD CVE records in ${durationMs}ms`);

      return {
        sourceName: this.name,
        records,
        durationMs,
        success: true
      };
    } catch (err: any) {
      const durationMs = Date.now() - startTime;
      console.error(`[${this.name}] Error fetching NVD records:`, err.message);
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
