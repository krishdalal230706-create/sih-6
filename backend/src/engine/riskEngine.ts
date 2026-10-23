import { Organization, RiskContributor } from '../types.js';

export interface CalculatedRiskResult {
  overallRiskScore: number;
  riskTrend: 'RISING' | 'STABLE' | 'FALLING';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  categoryScores: {
    authentication: number;
    networkSecurity: number;
    dataSecurity: number;
    endpointSecurity: number;
    userRisk: number;
  };
  contributors: RiskContributor[];
  explanation: string[];
  formulaDetails: {
    authenticationWeight: string;
    networkWeight: string;
    dataWeight: string;
    vulnerabilitiesWeight: string;
    controlsWeight: string;
    incidentsWeight: string;
  };
}

export function calculateOrganizationRisk(org: Organization, activeIncidentsCount: number = 2): CalculatedRiskResult {
  const authScore = org.riskBreakdown.authentication;
  const netScore = org.riskBreakdown.networkSecurity;
  const dataScore = org.riskBreakdown.dataSecurity;
  const endScore = org.riskBreakdown.endpointSecurity;
  const userScore = org.riskBreakdown.userRisk;

  // Transparent Weighted Formula:
  // Auth: 25%, Net: 20%, Data: 20%, Vulns: 20%, Controls: 10%, Incidents: 5%
  const vulnScore = Math.min(100, org.knownVulnerabilities * 4.5);
  const controlScore = Math.max(0, 100 - org.securityControls.length * 15);
  const incidentScore = Math.min(100, activeIncidentsCount * 25);

  const weightedScore = Math.round(
    authScore * 0.25 +
    netScore * 0.20 +
    dataScore * 0.20 +
    vulnScore * 0.20 +
    controlScore * 0.10 +
    incidentScore * 0.05
  );

  const overallRiskScore = Math.max(1, Math.min(100, weightedScore));

  let severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW';
  if (overallRiskScore >= 80) severity = 'CRITICAL';
  else if (overallRiskScore >= 65) severity = 'HIGH';
  else if (overallRiskScore >= 45) severity = 'MEDIUM';

  const contributors: RiskContributor[] = [
    {
      id: 'rc-1',
      name: 'Suspicious Authentication Anomalies',
      points: 25,
      category: 'Authentication',
      description: 'Multiple failed logins and unrecognized offshore device access.'
    },
    {
      id: 'rc-2',
      name: 'Domain Privilege Escalation',
      points: 20,
      category: 'Identity',
      description: 'Standard admin elevated to Domain Super Administrator.'
    },
    {
      id: 'rc-3',
      name: 'Unusual Outbound Data Transfer',
      points: 18,
      category: 'Data Exfiltration',
      description: '4.8 GB outbound HTTPS transfer to external cloud storage endpoint.'
    },
    {
      id: 'rc-4',
      name: 'Unregistered Fingerprint Device',
      points: 10,
      category: 'Endpoints',
      description: 'New device hardware hash initialized SSO token without MFA.'
    }
  ];

  const explanation = [
    `Authentication risk category sits at critical level (${authScore}/100) due to unenforced hardware MFA.`,
    `Active critical incidents contribute +${Math.round(incidentScore * 0.05)} points to overall risk exposure.`,
    `Known unpatched vulnerabilities (${org.knownVulnerabilities}) increase network vector exploitability by +${Math.round(vulnScore * 0.20)} points.`,
    `Data Sensitivity level (${org.dataSensitivity}) escalates breach impact multiplier.`
  ];

  return {
    overallRiskScore,
    riskTrend: org.riskTrend,
    severity,
    categoryScores: {
      authentication: authScore,
      networkSecurity: netScore,
      dataSecurity: dataScore,
      endpointSecurity: endScore,
      userRisk: userScore
    },
    contributors,
    explanation,
    formulaDetails: {
      authenticationWeight: '25% (Weight: 0.25)',
      networkWeight: '20% (Weight: 0.20)',
      dataWeight: '20% (Weight: 0.20)',
      vulnerabilitiesWeight: '20% (Weight: 0.20)',
      controlsWeight: '10% (Weight: 0.10)',
      incidentsWeight: '5% (Weight: 0.05)'
    }
  };
}
