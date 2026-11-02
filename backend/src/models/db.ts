import {
  Organization,
  AttackScenario,
  TelemetryEvent,
  Incident,
  ResponseAction,
  ThreatPattern,
  LedgerRecord,
  RiskContributor
} from '../types.js';
import { ledgerDb } from '../db/ledgerDb.js';

class DatabaseStore {
  public activeOrgId: string = 'org-1';

  public organizations: Record<string, Organization> = {
    'org-1': {
      id: 'org-1',
      name: 'Demo Bank',
      type: 'Banking and Financial Services',
      country: 'India',
      usersCount: 14200,
      criticalSystems: 48,
      internetFacingServices: 18,
      authenticationMethods: ['Password', 'SMS OTP / Biometric', 'Hardware Security Module (HSM)', 'RBAC'],
      securityControls: ['NextGen Firewall', 'Endpoint Detection & Response', 'Banking SIEM', 'DLP Vault'],
      knownVulnerabilities: 14,
      dataSensitivity: 'CRITICAL',
      previousIncidents: 3,
      riskScore: 84,
      riskTrend: 'RISING',
      lastUpdated: new Date().toISOString(),
      riskBreakdown: {
        authentication: 91,
        networkSecurity: 72,
        dataSecurity: 87,
        endpointSecurity: 68,
        userRisk: 54
      },
      activeThreatsCount: {
        critical: 4,
        high: 7,
        medium: 12,
        low: 18
      }
    },
    'org-2': {
      id: 'org-2',
      name: 'Hospital B',
      type: 'Healthcare & Lifesciences',
      usersCount: 6500,
      criticalSystems: 32,
      internetFacingServices: 12,
      authenticationMethods: ['Password', 'Smart Card', 'Basic MFA'],
      securityControls: ['Firewall', 'HIPAA Log Vault'],
      knownVulnerabilities: 9,
      dataSensitivity: 'CRITICAL',
      previousIncidents: 1,
      riskScore: 64,
      riskTrend: 'STABLE',
      lastUpdated: new Date().toISOString(),
      riskBreakdown: {
        authentication: 68,
        networkSecurity: 58,
        dataSecurity: 72,
        endpointSecurity: 60,
        userRisk: 50
      },
      activeThreatsCount: {
        critical: 1,
        high: 4,
        medium: 8,
        low: 12
      }
    },
    'org-3': {
      id: 'org-3',
      name: 'University C',
      type: 'Education & Research',
      usersCount: 28000,
      criticalSystems: 25,
      internetFacingServices: 45,
      authenticationMethods: ['CAS SSO', 'Password'],
      securityControls: ['Edge Router ACL'],
      knownVulnerabilities: 27,
      dataSensitivity: 'HIGH',
      previousIncidents: 5,
      riskScore: 58,
      riskTrend: 'STABLE',
      lastUpdated: new Date().toISOString(),
      riskBreakdown: {
        authentication: 62,
        networkSecurity: 65,
        dataSecurity: 50,
        endpointSecurity: 55,
        userRisk: 58
      },
      activeThreatsCount: {
        critical: 2,
        high: 5,
        medium: 14,
        low: 22
      }
    },
    'org-4': {
      id: 'org-4',
      name: 'FinTech Corp',
      type: 'Financial Technology',
      usersCount: 1200,
      criticalSystems: 18,
      internetFacingServices: 14,
      authenticationMethods: ['FIDO2 WebAuthn', 'OAuth2 / OIDC'],
      securityControls: ['Zero Trust Network', 'EDR', 'Cloud SIEM'],
      knownVulnerabilities: 4,
      dataSensitivity: 'CRITICAL',
      previousIncidents: 1,
      riskScore: 76,
      riskTrend: 'RISING',
      lastUpdated: new Date().toISOString(),
      riskBreakdown: {
        authentication: 78,
        networkSecurity: 82,
        dataSecurity: 75,
        endpointSecurity: 65,
        userRisk: 48
      },
      activeThreatsCount: {
        critical: 3,
        high: 5,
        medium: 9,
        low: 11
      }
    },
    'org-5': {
      id: 'org-5',
      name: 'Insurance Group',
      type: 'Insurance & Risk Underwriting',
      usersCount: 4800,
      criticalSystems: 22,
      internetFacingServices: 10,
      authenticationMethods: ['Hardware Token', 'Password + SMS'],
      securityControls: ['DLP', 'WAF', 'Antivirus'],
      knownVulnerabilities: 6,
      dataSensitivity: 'HIGH',
      previousIncidents: 2,
      riskScore: 52,
      riskTrend: 'FALLING',
      lastUpdated: new Date().toISOString(),
      riskBreakdown: {
        authentication: 50,
        networkSecurity: 48,
        dataSecurity: 56,
        endpointSecurity: 52,
        userRisk: 42
      },
      activeThreatsCount: {
        critical: 0,
        high: 3,
        medium: 7,
        low: 15
      }
    }
  };

  public attackScenarios: AttackScenario[] = [
    {
      id: 'scenario-1',
      name: 'Phishing & Employee Account Takeover',
      description: 'Simulated spear-phishing email targeting branch teller credentials, creating unauthorized session tokens and triggering automated SOC alerts.',
      probability: 78,
      impact: 'CRITICAL',
      scenarioRisk: 89,
      criticalWeakPoint: 'Weak Authentication & Lack of FIDO2 MFA',
      explanation: 'The absence of hardware-backed multi-factor authentication allows credential theft to instantly grant access to core identity providers.',
      nodes: [
        {
          id: 'node-1',
          stage: 'Spear Phishing',
          name: 'Executive Spear Phishing Email',
          risk: 45,
          probability: 85,
          impact: 'MEDIUM',
          affectedAsset: 'Branch Teller Workstation (asset-workstations)',
          reason: 'Simulated phishing lure bypassed legacy SPF/DKIM filters.',
          exploitability: 'High',
          recommendedControl: 'Advanced Email Filter & Security Awareness Training'
        },
        {
          id: 'node-2',
          stage: 'Account Compromise',
          name: 'Banking SSO Session Hijack',
          risk: 91,
          probability: 78,
          impact: 'HIGH',
          affectedAsset: 'Authentication Server & HSM Cluster (asset-auth)',
          reason: 'Stolen teller credentials used from unauthorized offshore IP.',
          exploitability: 'Critical',
          recommendedControl: 'Enforce FIDO2 WebAuthn Hardware Keys & Geo-Fencing'
        },
        {
          id: 'node-3',
          stage: 'Lateral Escalation',
          name: 'Privileged Escalation to Branch Manager',
          risk: 88,
          probability: 70,
          impact: 'CRITICAL',
          affectedAsset: 'Active Directory Domain Controller (asset-network)',
          reason: 'Standard teller role attempted elevation to branch supervisor.',
          exploitability: 'High',
          recommendedControl: 'Implement LAPS & Privileged Access Management (PAM)'
        }
      ]
    },
    {
      id: 'scenario-2',
      name: 'Distributed Credential Stuffing on NetBanking',
      description: 'Simulated automated botnet attempting credential stuffing against Demo Bank Internet Banking portal, generating rate-limiting and WAF telemetry.',
      probability: 82,
      impact: 'HIGH',
      scenarioRisk: 84,
      criticalWeakPoint: 'WAF Rate Limiting & CAPTCHA Thresholds',
      explanation: 'Distributed proxy botnets rotating IP addresses to circumvent basic IP blocklists and brute-force customer web accounts.',
      nodes: [
        {
          id: 'node-201',
          stage: 'Proxy Reconnaissance',
          name: 'Distributed Botnet Scanning',
          risk: 55,
          probability: 90,
          impact: 'MEDIUM',
          affectedAsset: 'Internet Banking Server (asset-netbank)',
          reason: '340 distinct residential proxy IPs probing customer login endpoint.',
          exploitability: 'High',
          recommendedControl: 'Bot Management & Web Application Firewall (WAF)'
        },
        {
          id: 'node-202',
          stage: 'Credential Stuffing Burst',
          name: '1,840 Synthetic Failed Logins / Min',
          risk: 85,
          probability: 82,
          impact: 'HIGH',
          affectedAsset: 'Internet Banking Reverse Proxy (asset-netbank)',
          reason: 'Automated replay of compromised credential dumps.',
          exploitability: 'High',
          recommendedControl: 'Step-Up OTP Challenge & Exponential Backoff'
        },
        {
          id: 'node-203',
          stage: 'Targeted Account Lockout',
          name: 'Defensive Account Protection Triggered',
          risk: 40,
          probability: 95,
          impact: 'LOW',
          affectedAsset: 'Customer Information Database (asset-custdb)',
          reason: 'Automated lockout rules engaged after 5 failed attempts.',
          exploitability: 'Low',
          recommendedControl: 'Adaptive Risk-Based Authentication'
        }
      ]
    },
    {
      id: 'scenario-3',
      name: 'Payment Gateway Fraud & Velocity Burst',
      description: 'Simulated micro-debit fraud campaign testing stolen virtual payment addresses (VPAs) through Demo Bank UPI Gateway switch.',
      probability: 74,
      impact: 'CRITICAL',
      scenarioRisk: 92,
      criticalWeakPoint: 'UPI Velocity Throttling & Fraud Rule Engine',
      explanation: 'High-frequency micro-transactions designed to validate compromised cards or UPI handles without triggering legacy bulk-amount rules.',
      nodes: [
        {
          id: 'node-301',
          stage: 'VPA Probe',
          name: 'Automated Micro-Debit Probing (Rs. 1.00)',
          risk: 68,
          probability: 85,
          impact: 'MEDIUM',
          affectedAsset: 'UPI & Payment Gateway Processor (asset-payment)',
          reason: '420 transactions/min initiated from single merchant node.',
          exploitability: 'Critical',
          recommendedControl: 'Real-time AI Velocity Scoring & Terminal Throttling'
        },
        {
          id: 'node-302',
          stage: 'Clearing Injection',
          name: 'Unusual Settlement Account Routing',
          risk: 94,
          probability: 75,
          impact: 'CRITICAL',
          affectedAsset: 'Core Banking System (asset-cbs)',
          reason: 'Simulated illicit payout destination flagged by AML heuristic.',
          exploitability: 'Critical',
          recommendedControl: 'Instant Settlement Freeze & Merchant VPA Revocation'
        }
      ]
    },
    {
      id: 'scenario-4',
      name: 'Controlled Ransomware Simulation',
      description: 'Safe, non-destructive simulation of ransomware propagation on branch desktop network testing behavioral EDR detection and file canary traps.',
      probability: 60,
      impact: 'CRITICAL',
      scenarioRisk: 88,
      criticalWeakPoint: 'Endpoint Peripheral Control & Immutable Backups',
      explanation: 'Demonstrating how behavioral canary file detection catches suspicious mass-file renames before core banking data stores can be reached.',
      nodes: [
        {
          id: 'node-401',
          stage: 'Initial Drop',
          name: 'Malicious Document Macro Execution',
          risk: 70,
          probability: 75,
          impact: 'HIGH',
          affectedAsset: 'Branch Teller Workstations (asset-workstations)',
          reason: 'Macro script attempted synthetic canary encryption in temp folder.',
          exploitability: 'High',
          recommendedControl: 'Behavioral EDR Agent with Automatic Host Isolation'
        },
        {
          id: 'node-402',
          stage: 'Canary Tripwire',
          name: 'Canary File Modification Detected',
          risk: 90,
          probability: 60,
          impact: 'CRITICAL',
          affectedAsset: 'Backup & Disaster Recovery System (asset-dr)',
          reason: 'Canary trap triggered instant process kill and snapshot rollback.',
          exploitability: 'Critical',
          recommendedControl: 'Immutable WORM Storage & Automated Air-Gapped Snapshots'
        }
      ]
    },
    {
      id: 'scenario-5',
      name: 'Insider Threat & Unauthorized CIF Access',
      description: 'Simulated employee extracting customer information records outside authorized clearing shifts and attempting bulk local export.',
      probability: 55,
      impact: 'HIGH',
      scenarioRisk: 79,
      criticalWeakPoint: 'Database Activity Monitoring (DAM) & Data Masking',
      explanation: 'Authorized staff leveraging legitimate credentials during unusual hours to perform excessive customer queries.',
      nodes: [
        {
          id: 'node-501',
          stage: 'Off-Hours Access',
          name: 'Late-Night Core DB Query (02:14 AM IST)',
          risk: 65,
          probability: 80,
          impact: 'MEDIUM',
          affectedAsset: 'Customer Information Database (asset-custdb)',
          reason: '10,000+ CIF records queried outside standard branch operating hours.',
          exploitability: 'Medium',
          recommendedControl: 'Contextual Access Windows & Time-Bound Session Grants'
        },
        {
          id: 'node-502',
          stage: 'Egress Attempt',
          name: 'Removable Storage Media Insertion',
          risk: 86,
          probability: 65,
          impact: 'HIGH',
          affectedAsset: 'Branch Employee Workstations (asset-workstations)',
          reason: 'Unauthorized USB drive connected to export CIF CSV.',
          exploitability: 'High',
          recommendedControl: 'Endpoint DLP & Strict Removable Media Lockdown'
        }
      ]
    },
    {
      id: 'scenario-6',
      name: 'Third-Party Software Dependency Flaw',
      description: 'Vulnerability simulation in open-source banking integration library (e.g. ISO 8583 message parser) triggering automated virtual patching.',
      probability: 70,
      impact: 'CRITICAL',
      scenarioRisk: 86,
      criticalWeakPoint: 'Software Supply Chain Security & SBOM Auditing',
      explanation: 'Zero-day or unpatched vulnerability in an embedded third-party library enabling remote code execution on banking gateways.',
      nodes: [
        {
          id: 'node-601',
          stage: 'Dependency Alert',
          name: 'Known CVE in ISO 8583 Message Parser',
          risk: 85,
          probability: 75,
          impact: 'HIGH',
          affectedAsset: 'UPI & Payment Gateway Processor (asset-payment)',
          reason: 'Buffer overflow vulnerability detected via automated SBOM sync.',
          exploitability: 'Critical',
          recommendedControl: 'Software Bill of Materials (SBOM) & Automated SCA'
        },
        {
          id: 'node-602',
          stage: 'Virtual Patching',
          name: 'WAF Inline Signature Deployment',
          risk: 30,
          probability: 95,
          impact: 'LOW',
          affectedAsset: 'Bank Internal Core Network (asset-network)',
          reason: 'Signature rule deployed to drop exploit payloads at edge firewall.',
          exploitability: 'Low',
          recommendedControl: 'Next-Gen Firewall IPS & Virtual Patching Engine'
        }
      ]
    }
  ];

  public telemetryStream: TelemetryEvent[] = [
    {
      id: 'tel-101',
      timestamp: '09:42:15',
      eventType: 'FAILED_LOGIN',
      sourceIp: '198.51.100.42',
      user: 'admin@demobank.com',
      deviceId: 'DEV-83921',
      severity: 'MEDIUM',
      details: '15 consecutive failed login attempts detected within 30 seconds.'
    },
    {
      id: 'tel-102',
      timestamp: '09:42:48',
      eventType: 'SUCCESSFUL_LOGIN',
      sourceIp: '198.51.100.42',
      user: 'admin@demobank.com',
      deviceId: 'DEV-83921',
      severity: 'HIGH',
      details: 'Successful authentication from unrecognized IP address.'
    },
    {
      id: 'tel-103',
      timestamp: '09:43:10',
      eventType: 'NEW_DEVICE',
      sourceIp: '198.51.100.42',
      user: 'admin@demobank.com',
      deviceId: 'DEV-UNKNOWN-889',
      severity: 'HIGH',
      details: 'Unregistered device fingerprint attempting SSO session initialization.'
    },
    {
      id: 'tel-104',
      timestamp: '09:43:35',
      eventType: 'UNUSUAL_LOCATION',
      sourceIp: '198.51.100.42',
      user: 'admin@demobank.com',
      deviceId: 'DEV-UNKNOWN-889',
      severity: 'HIGH',
      details: 'Geographic discrepancy: User logged in from Frankfurt, Germany (Normal: New York, USA).'
    },
    {
      id: 'tel-105',
      timestamp: '09:44:02',
      eventType: 'PRIVILEGE_ESCALATION',
      sourceIp: '198.51.100.42',
      user: 'admin@demobank.com',
      deviceId: 'DEV-UNKNOWN-889',
      severity: 'CRITICAL',
      details: 'Role change requested: Standard Administrator → Domain Super Administrator.'
    },
    {
      id: 'tel-106',
      timestamp: '09:44:50',
      eventType: 'LARGE_DATA_TRANSFER',
      sourceIp: '198.51.100.42',
      user: 'admin@demobank.com',
      deviceId: 'DEV-UNKNOWN-889',
      severity: 'CRITICAL',
      details: 'Outbound encrypted HTTPS transfer of 4.8 GB to external IP endpoint.'
    }
  ];

  public incidents: Incident[] = [
    // org-1 Demo Bank
    {
      id: 'inc-1',
      incidentId: 'INC-2026-8891',
      orgId: 'org-1',
      title: 'Possible Account Compromise & Exfiltration',
      threatType: 'Credential Hijack & Data Exfiltration',
      severity: 'CRITICAL',
      status: 'Detected',
      detectionTime: '2026-09-04 09:44:02',
      affectedAsset: 'Core Identity & Customer Database (DB-PROD-01)',
      confidence: 92,
      riskScore: 91,
      description: 'Multiple authentication anomalies (failed logins, unknown device, offshore IP) followed by privileged access and 4.8 GB outbound data transfer.',
      timeline: [
        {
          id: 't-1',
          time: '09:42:15',
          title: 'Multiple Failed Logins',
          description: '15 failed logins targeting admin@demobank.com',
          type: 'DETECTION'
        },
        {
          id: 't-2',
          time: '09:42:48',
          title: 'Successful Authentication',
          description: 'Login from suspicious external IP 198.51.100.42',
          type: 'RISK_INCREASE'
        },
        {
          id: 't-3',
          time: '09:44:02',
          title: 'Privilege Escalation Detected',
          description: 'Role elevated to Domain Super Admin',
          type: 'DETECTION'
        }
      ],
      rawLogs: {
        employee: 'John Doe (Senior Financial Admin)',
        internalIp: '10.0.4.21',
        deviceId: 'DEV-83921',
        account: 'admin@demobank.com',
        rawLogText: 'TIMESTAMP=2026-09-04T09:42:15Z SRC=198.51.100.42 USER=admin@demobank.com DEV=DEV-83921 EVENT=FAILED_LOGIN ATTEMPTS=15 STATUS=DENIED; ROLE_CHANGE=SUPERADMIN PRIVILEGE=ELEVATED EXFIL_BYTES=4800000000'
      }
    },
    // org-2 City Hospital
    {
      id: 'inc-201',
      incidentId: 'INC-2026-9021',
      orgId: 'org-2',
      title: 'HIPAA EHR Data Access Anomaly & Ransomware Staging',
      threatType: 'Healthcare Record Access & Ransomware Vector',
      severity: 'CRITICAL',
      status: 'Detected',
      detectionTime: '2026-09-04 08:30:00',
      affectedAsset: 'EHR Database Server & Patient Records Vault',
      confidence: 90,
      riskScore: 78,
      description: 'Off-hours bulk queries targeting patient electronic health records followed by unauthorized process injection.',
      timeline: [
        {
          id: 't-201',
          time: '08:30:00',
          title: 'Bulk Patient EHR Export Alert',
          description: '12,000 patient records queried outside shift hours',
          type: 'DETECTION'
        }
      ]
    },
    // org-3 State University
    {
      id: 'inc-301',
      incidentId: 'INC-2026-3341',
      orgId: 'org-3',
      title: 'Academic Research Database Credential Spray',
      threatType: 'Credential Spray & CAS Exploitation',
      severity: 'HIGH',
      status: 'Investigating',
      detectionTime: '2026-09-04 07:15:00',
      affectedAsset: 'CAS Central Authentication Server & Research Repository',
      confidence: 85,
      riskScore: 68,
      description: 'Automated credential spray targeting faculty CAS SSO endpoints from external IP subnet.',
      timeline: [
        {
          id: 't-301',
          time: '07:15:00',
          title: 'CAS SSO Anomaly Stream',
          description: '4,500 login attempts across 200 faculty accounts',
          type: 'DETECTION'
        }
      ]
    },
    // org-4 FinTech Corp
    {
      id: 'inc-401',
      incidentId: 'INC-2026-5510',
      orgId: 'org-4',
      title: 'AWS Cloud IAM Secret Key Exposure & Session Theft',
      threatType: 'Cloud IAM Breach & Cookie Theft',
      severity: 'CRITICAL',
      status: 'Detected',
      detectionTime: '2026-09-04 09:10:00',
      affectedAsset: 'AWS Cloud Production IAM Console & Payment API',
      confidence: 94,
      riskScore: 82,
      description: 'Stolen developer session cookie used to query AWS IAM Secrets Manager and extract production database credentials.',
      timeline: [
        {
          id: 't-401',
          time: '09:10:00',
          title: 'Stolen Cookie Cloud Login',
          description: 'Developer session initialized from unrecognized device',
          type: 'DETECTION'
        }
      ]
    },
    // org-5 Insurance Group
    {
      id: 'inc-501',
      incidentId: 'INC-2026-1189',
      orgId: 'org-5',
      title: 'Claims Underwriting Portal Data Crawl',
      threatType: 'Data Loss Prevention (DLP) Alert',
      severity: 'HIGH',
      status: 'Investigating',
      detectionTime: '2026-09-04 06:45:00',
      affectedAsset: 'Claims Management Portal Gateway',
      confidence: 80,
      riskScore: 60,
      description: 'High-frequency HTTP GET requests exporting policy underwriting files to unencrypted external target.',
      timeline: [
        {
          id: 't-501',
          time: '06:45:00',
          title: 'DLP Policy Violation Alert',
          description: 'Export threshold exceeded on insurance claims database',
          type: 'DETECTION'
        }
      ]
    }
  ];

  public responseActions: ResponseAction[] = [
    // org-1 Demo Bank
    {
      id: 'act-1',
      incidentId: 'inc-1',
      orgId: 'org-1',
      title: 'Force Immediate Re-authentication & Revoke Active SSO Tokens',
      priority: 'CRITICAL',
      reason: 'Revokes active hijacked SSO tokens across identity providers.',
      estimatedRiskReduction: 12,
      status: 'Pending',
      effort: 'Low',
      estimatedTime: '15 mins',
      isQuickWin: true
    },
    {
      id: 'act-2',
      incidentId: 'inc-1',
      orgId: 'org-1',
      title: 'Restrict & Suspend Privileged Account (admin@demobank.com)',
      priority: 'CRITICAL',
      reason: 'Prevents unauthorized domain admin execution and lateral movement.',
      estimatedRiskReduction: 8,
      status: 'Pending',
      effort: 'Low',
      estimatedTime: '30 mins',
      isQuickWin: true
    },
    {
      id: 'act-3',
      incidentId: 'inc-1',
      orgId: 'org-1',
      title: 'Isolate & Quarantine Suspicious Device (DEV-UNKNOWN-889)',
      priority: 'HIGH',
      reason: 'Blocks network traffic from untrusted device fingerprint.',
      estimatedRiskReduction: 5,
      status: 'Pending',
      effort: 'Medium',
      estimatedTime: '2 hours',
      isQuickWin: false
    },
    {
      id: 'act-4',
      incidentId: 'inc-1',
      orgId: 'org-1',
      title: 'Block Outbound IP (198.51.100.42) on Perimeter Firewall',
      priority: 'HIGH',
      reason: 'Cuts active exfiltration command-and-control connection.',
      estimatedRiskReduction: 4,
      status: 'Pending',
      effort: 'Low',
      estimatedTime: '10 mins',
      isQuickWin: true
    },

    // org-2 City Hospital
    {
      id: 'act-201',
      incidentId: 'inc-201',
      orgId: 'org-2',
      title: 'Enforce Smart-Card Dual MFA on Electronic Health Record (EHR) System',
      priority: 'CRITICAL',
      reason: 'Prevents unauthorized off-hours access to patient HIPAA record vault.',
      estimatedRiskReduction: 14,
      status: 'Pending',
      effort: 'Medium',
      estimatedTime: '4 hours',
      isQuickWin: true
    },
    {
      id: 'act-202',
      incidentId: 'inc-201',
      orgId: 'org-2',
      title: 'Isolate Vulnerable Medical Device Subnet (VLAN-MED-44)',
      priority: 'CRITICAL',
      reason: 'Blocks lateral movement of ransomware payload to critical care systems.',
      estimatedRiskReduction: 10,
      status: 'Pending',
      effort: 'Low',
      estimatedTime: '20 mins',
      isQuickWin: true
    },
    {
      id: 'act-203',
      incidentId: 'inc-201',
      orgId: 'org-2',
      title: 'Enable Behavioral Anti-Ransomware Rollback on Hospital Workstations',
      priority: 'HIGH',
      reason: 'Protects hospital endpoints against encrypted file payload execution.',
      estimatedRiskReduction: 8,
      status: 'Pending'
    },
    {
      id: 'act-204',
      incidentId: 'inc-201',
      orgId: 'org-2',
      title: 'Revoke Off-Hours External Remote Access for Contract Doctors',
      priority: 'HIGH',
      reason: 'Eliminates unverified remote connections into the hospital core network.',
      estimatedRiskReduction: 6,
      status: 'Pending'
    },

    // org-3 State University
    {
      id: 'act-301',
      incidentId: 'inc-301',
      orgId: 'org-3',
      title: 'Require CAS SSO Multi-Factor Challenge for All Research DB Access',
      priority: 'CRITICAL',
      reason: 'Stops automated credential spray attacks against faculty research repositories.',
      estimatedRiskReduction: 15,
      status: 'Pending'
    },
    {
      id: 'act-302',
      incidentId: 'inc-301',
      orgId: 'org-3',
      title: 'Block Automated IP Subnet 198.51.200.0/24 on University Edge Routers',
      priority: 'CRITICAL',
      reason: 'Blocks active botnet IP addresses conducting credential spray.',
      estimatedRiskReduction: 10,
      status: 'Pending'
    },
    {
      id: 'act-303',
      incidentId: 'inc-301',
      orgId: 'org-3',
      title: 'Terminate Compromised Student & Faculty Sessions',
      priority: 'HIGH',
      reason: 'Purges invalid SSO tokens issued during spray attack.',
      estimatedRiskReduction: 7,
      status: 'Pending'
    },
    {
      id: 'act-304',
      incidentId: 'inc-301',
      orgId: 'org-3',
      title: 'Deploy WAF Rate Limiting Rules on Academic Portal Gateway',
      priority: 'HIGH',
      reason: 'Prevents brute force authentication scanning against public login portals.',
      estimatedRiskReduction: 5,
      status: 'Pending'
    },

    // org-4 FinTech Corp
    {
      id: 'act-401',
      incidentId: 'inc-401',
      orgId: 'org-4',
      title: 'Rotate AWS IAM Production Admin Access Keys & Revoke Stolen Cookies',
      priority: 'CRITICAL',
      reason: 'Inactivates compromised cloud credentials and invalidates stolen developer sessions.',
      estimatedRiskReduction: 16,
      status: 'Pending'
    },
    {
      id: 'act-402',
      incidentId: 'inc-401',
      orgId: 'org-4',
      title: 'Enforce FIDO2 WebAuthn Hardware Keys on Developer Accounts',
      priority: 'CRITICAL',
      reason: 'Provides hardware-backed anti-phishing MFA across engineering teams.',
      estimatedRiskReduction: 12,
      status: 'Pending'
    },
    {
      id: 'act-403',
      incidentId: 'inc-401',
      orgId: 'org-4',
      title: 'Restrict Production API Access to Zero-Trust Microsegmented IP Range',
      priority: 'HIGH',
      reason: 'Prevents unauthorized IP addresses from invoking payment microservices.',
      estimatedRiskReduction: 8,
      status: 'Pending'
    },
    {
      id: 'act-404',
      incidentId: 'inc-401',
      orgId: 'org-4',
      title: 'Deploy EDR Memory Inspection Agent on Developer Laptops',
      priority: 'HIGH',
      reason: 'Detects and terminates browser infostealer malware in real-time.',
      estimatedRiskReduction: 6,
      status: 'Pending'
    },

    // org-5 Insurance Group
    {
      id: 'act-501',
      incidentId: 'inc-501',
      orgId: 'org-5',
      title: 'Enable Data Loss Prevention (DLP) Block Rules on Claims Exports',
      priority: 'CRITICAL',
      reason: 'Prevents unauthorized bulk downloads of insurance policy records.',
      estimatedRiskReduction: 14,
      status: 'Pending'
    },
    {
      id: 'act-502',
      incidentId: 'inc-501',
      orgId: 'org-5',
      title: 'Enforce Context-Aware Adaptive Auth for Off-Hours Claims Admins',
      priority: 'CRITICAL',
      reason: 'Challenges off-hours portal logins with step-up MFA.',
      estimatedRiskReduction: 10,
      status: 'Pending'
    },
    {
      id: 'act-503',
      incidentId: 'inc-501',
      orgId: 'org-5',
      title: 'Apply WAF Virtual Patching for Unpatched DMZ Portal Gateway',
      priority: 'HIGH',
      reason: 'Mitigates known gateway vulnerabilities until scheduled patch window.',
      estimatedRiskReduction: 8,
      status: 'Pending'
    },
    {
      id: 'act-504',
      incidentId: 'inc-501',
      orgId: 'org-5',
      title: 'Restrict Privileged Claims Underwriter Export Quotas',
      priority: 'HIGH',
      reason: 'Enforces rate limits on claims record exports per user hour.',
      estimatedRiskReduction: 5,
      status: 'Pending'
    }
  ];

  public threatPatterns: ThreatPattern[] = [
    {
      id: 'tp-1',
      patternCode: 'TH-7821',
      originOrgId: 'org-1',
      originOrgName: 'Bank A',
      patternSequence: [
        'FAILED_LOGIN',
        'SUCCESSFUL_LOGIN',
        'NEW_DEVICE',
        'UNUSUAL_LOCATION',
        'PRIVILEGE_ESCALATION',
        'LARGE_DATA_TRANSFER'
      ],
      severity: 'CRITICAL',
      confidence: 94,
      status: 'Confirmed',
      hash: 'a8f3b29c91d4e5f670123456789abcdef0123456789abcdef0123456789ab2bd',
      createdAt: '2026-09-04 09:45:10',
      isShared: true
    },
    {
      id: 'tp-2',
      patternCode: 'TH-4019',
      originOrgId: 'org-4',
      originOrgName: 'FinTech Corp',
      patternSequence: [
        'FAILED_LOGIN',
        'NEW_DEVICE',
        'PRIVILEGE_ESCALATION',
        'UNUSUAL_ACCESS'
      ],
      severity: 'HIGH',
      confidence: 88,
      status: 'Confirmed',
      hash: 'e7c2d1b09876543210fedcba9876543210fedcba9876543210fedcba98765432',
      createdAt: '2026-09-03 14:20:00',
      isShared: true
    }
  ];

  public ledgerRecords: LedgerRecord[] = ledgerDb.getAllBlocks();

  private initialSnapshot: string;

  constructor() {
    this.initialSnapshot = JSON.stringify({
      activeOrgId: this.activeOrgId,
      organizations: this.organizations,
      attackScenarios: this.attackScenarios,
      telemetryStream: this.telemetryStream,
      incidents: this.incidents,
      responseActions: this.responseActions,
      threatPatterns: this.threatPatterns
    });
  }

  public resetToBaseline(): void {
    const baseline = JSON.parse(this.initialSnapshot);
    this.activeOrgId = baseline.activeOrgId;
    this.organizations = baseline.organizations;
    this.attackScenarios = baseline.attackScenarios;
    this.telemetryStream = baseline.telemetryStream;
    this.incidents = baseline.incidents;
    this.responseActions = baseline.responseActions;
    this.threatPatterns = baseline.threatPatterns;
    this.ledgerRecords = ledgerDb.resetToBaseline();
  }

  public registerOrganization(org: Organization): void {
    this.organizations[org.id] = org;
  }

  public getActiveOrganization(): Organization {
    return this.organizations[this.activeOrgId] || this.organizations['org-1'];
  }
}

export const db = new DatabaseStore();
