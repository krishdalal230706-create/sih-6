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
      type: 'Financial Services',
      usersCount: 14200,
      criticalSystems: 48,
      internetFacingServices: 18,
      authenticationMethods: ['Password', 'SMS OTP', 'Legacy SSO'],
      securityControls: ['Firewall', 'Endpoint Antivirus', 'Basic SIEM'],
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
      name: 'City Hospital',
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
      name: 'State University',
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
      name: 'Phishing → Account Compromise',
      description: 'Attacker sends spear-phishing email targeting financial admin credentials, escalates privilege via unpatched SSO, and queries customer PII.',
      probability: 78,
      impact: 'CRITICAL',
      scenarioRisk: 89,
      criticalWeakPoint: 'Weak Authentication & Lack of FIDO2 MFA',
      explanation: 'The absence of hardware-backed multi-factor authentication allows credential theft to instantly grant access to core identity providers.',
      nodes: [
        {
          id: 'node-1',
          stage: 'Phishing Email',
          name: 'Executive Spear Phishing',
          risk: 45,
          probability: 85,
          impact: 'MEDIUM',
          affectedAsset: 'Employee Mailbox (admin@demobank.com)',
          reason: 'Phishing email bypassed basic SPF/DKIM filters.',
          exploitability: 'High',
          recommendedControl: 'Advanced Email Security & Security Awareness Training'
        },
        {
          id: 'node-2',
          stage: 'Account Compromise',
          name: 'Identity Provider SSO Session Hijack',
          risk: 91,
          probability: 78,
          impact: 'HIGH',
          affectedAsset: 'Identity Provider (Okta / Azure AD)',
          reason: 'Password reused and SMS OTP intercepted.',
          exploitability: 'Critical',
          recommendedControl: 'Enforce FIDO2 WebAuthn / Hardware Keys'
        },
        {
          id: 'node-3',
          stage: 'Privilege Escalation',
          name: 'Domain Admin Account Escalation',
          risk: 88,
          probability: 70,
          impact: 'CRITICAL',
          affectedAsset: 'Active Directory Core',
          reason: 'Service account credentials stored in plain text memory.',
          exploitability: 'High',
          recommendedControl: 'Implement LAPS and Privileged Access Management (PAM)'
        },
        {
          id: 'node-4',
          stage: 'Data Access',
          name: 'Core Banking DB Lateral Movement',
          risk: 85,
          probability: 65,
          impact: 'CRITICAL',
          affectedAsset: 'Core Customer Database (DB-PROD-01)',
          reason: 'Internal database port open without microsegmentation.',
          exploitability: 'High',
          recommendedControl: 'Zero Trust Microsegmentation & Database Firewall'
        },
        {
          id: 'node-5',
          stage: 'Data Exfiltration',
          name: 'Encrypted Cloud Storage Exfiltration',
          risk: 94,
          probability: 60,
          impact: 'CRITICAL',
          affectedAsset: 'External S3 Storage Bucket',
          reason: 'No egress filtering on outbound HTTPS traffic.',
          exploitability: 'Medium',
          recommendedControl: 'Data Loss Prevention (DLP) & CASB Proxy'
        }
      ]
    },
    {
      id: 'scenario-2',
      name: 'Credential Theft & Session Hijacking',
      description: 'Malicious infostealer malware extracts session tokens from browser memory, impersonating active developer sessions.',
      probability: 72,
      impact: 'HIGH',
      scenarioRisk: 81,
      criticalWeakPoint: 'Endpoint Memory Protection & Token Expiration',
      explanation: 'Long-lived session cookies without IP binding enable session reuse across untrusted devices.',
      nodes: [
        {
          id: 'node-201',
          stage: 'Infostealer Execution',
          name: 'Browser Password Stealer',
          risk: 65,
          probability: 80,
          impact: 'MEDIUM',
          affectedAsset: 'Developer Workstation (DEV-WS-44)',
          reason: 'Untrusted software installation.',
          exploitability: 'High',
          recommendedControl: 'Endpoint Detection and Response (EDR)'
        },
        {
          id: 'node-202',
          stage: 'Token Theft',
          name: 'Cookie Hijacking',
          risk: 82,
          probability: 75,
          impact: 'HIGH',
          affectedAsset: 'GitHub Enterprise / AWS Console',
          reason: 'Session cookies lacked HTTPOnly and SameSite flags.',
          exploitability: 'High',
          recommendedControl: 'Shorten Token TTL & Bind Sessions to Client IP'
        },
        {
          id: 'node-203',
          stage: 'Cloud Access',
          name: 'Unrestricted API Key Access',
          risk: 88,
          probability: 68,
          impact: 'CRITICAL',
          affectedAsset: 'AWS Cloud Production Environment',
          reason: 'Hardcoded credentials in developer environment.',
          exploitability: 'Critical',
          recommendedControl: 'AWS IAM Identity Center & Secrets Manager'
        }
      ]
    },
    {
      id: 'scenario-3',
      name: 'Privilege Escalation via Vulnerable Service',
      description: 'Attacker leverages CVE-2024-4891 in internet-facing web server to execute arbitrary commands as root.',
      probability: 68,
      impact: 'CRITICAL',
      scenarioRisk: 86,
      criticalWeakPoint: 'Unpatched Known Vulnerabilities in DMZ',
      explanation: 'Missing security patches on web application gateways provide direct remote code execution.',
      nodes: [
        {
          id: 'node-301',
          stage: 'External Recon',
          name: 'Port Scanning & Service Discovery',
          risk: 40,
          probability: 90,
          impact: 'LOW',
          affectedAsset: 'Public Gateway (gw.demobank.com)',
          reason: 'Public ports exposed without rate limiting.',
          exploitability: 'Medium',
          recommendedControl: 'Web Application Firewall (WAF) & Rate Limiting'
        },
        {
          id: 'node-302',
          stage: 'Exploitation',
          name: 'RCE via CVE-2024-4891',
          risk: 92,
          probability: 72,
          impact: 'CRITICAL',
          affectedAsset: 'DMZ Gateway Server',
          reason: 'Known unpatched remote code execution vulnerability.',
          exploitability: 'Critical',
          recommendedControl: 'Patch Management & Virtual Patching WAF Rules'
        },
        {
          id: 'node-303',
          stage: 'Privilege Escalation',
          name: 'Local Kernel Exploit (Root)',
          risk: 89,
          probability: 65,
          impact: 'CRITICAL',
          affectedAsset: 'Linux Application Kernel',
          reason: 'Kernel vulnerable to privilege escalation.',
          exploitability: 'High',
          recommendedControl: 'Hardened Kernel OS & SELinux Policy'
        }
      ]
    },
    {
      id: 'scenario-4',
      name: 'Insider Threat Data Exfiltration',
      description: 'Disgruntled database administrator uses authorized credentials after hours to copy transaction logs to external media.',
      probability: 55,
      impact: 'HIGH',
      scenarioRisk: 74,
      criticalWeakPoint: 'Excessive Database Permissions & Absence of UEBA',
      explanation: 'Lack of User and Entity Behavior Analytics (UEBA) fails to flag massive off-hours data extraction.',
      nodes: [
        {
          id: 'node-401',
          stage: 'Unauthorized Access',
          name: 'After-Hours Admin Login',
          risk: 60,
          probability: 70,
          impact: 'MEDIUM',
          affectedAsset: 'Database Console',
          reason: 'No contextual access policies enforced for time of day.',
          exploitability: 'Medium',
          recommendedControl: 'Context-Aware Adaptive Authentication'
        },
        {
          id: 'node-402',
          stage: 'Data Query',
          name: 'Bulk Export of Financial Records',
          risk: 84,
          probability: 60,
          impact: 'HIGH',
          affectedAsset: 'Core Oracle DB',
          reason: 'No query rate limits or threshold alerts for DB admins.',
          exploitability: 'High',
          recommendedControl: 'Database Activity Monitoring (DAM) & Masking'
        }
      ]
    },
    {
      id: 'scenario-5',
      name: 'Ransomware Outbreak via Exposed RDP',
      description: 'Attacker brute-forces RDP port, deploys ransomware payload encrypting core file shares and local backups.',
      probability: 65,
      impact: 'CRITICAL',
      scenarioRisk: 90,
      criticalWeakPoint: 'Direct Exposed RDP Ports without MFA',
      explanation: 'Exposing Remote Desktop Protocol directly to the public internet without VPN protection.',
      nodes: [
        {
          id: 'node-501',
          stage: 'Initial Access',
          name: 'RDP Brute Force Attack',
          risk: 75,
          probability: 85,
          impact: 'HIGH',
          affectedAsset: 'Terminal Server (RDP-EXT-02)',
          reason: 'Port 3389 exposed to internet.',
          exploitability: 'Critical',
          recommendedControl: 'Close Public RDP Ports & Enforce VPN + MFA'
        },
        {
          id: 'node-502',
          stage: 'Malware Execution',
          name: 'LockBit Ransomware Deployment',
          risk: 95,
          probability: 70,
          impact: 'CRITICAL',
          affectedAsset: 'Internal File Storage (NAS-FINANCE)',
          reason: 'Antivirus signature database outdated.',
          exploitability: 'Critical',
          recommendedControl: 'Behavioral EDR with Ransomware Rollback'
        }
      ]
    },
    {
      id: 'scenario-6',
      name: 'Cloud Data Exfiltration via Misconfigured S3',
      description: 'Attacker locates publicly readable S3 bucket containing backup databases and downloads sensitive records.',
      probability: 82,
      impact: 'CRITICAL',
      scenarioRisk: 88,
      criticalWeakPoint: 'Cloud Misconfiguration & Public Bucket ACLs',
      explanation: 'Inadvertent public read access configured on cloud storage buckets containing sensitive records.',
      nodes: [
        {
          id: 'node-601',
          stage: 'Bucket Discovery',
          name: 'Automated Cloud Bucket Recon',
          risk: 50,
          probability: 95,
          impact: 'MEDIUM',
          affectedAsset: 'AWS S3 Bucket (demobank-backups-2026)',
          reason: 'Public read ACL enabled.',
          exploitability: 'High',
          recommendedControl: 'AWS S3 Block Public Access Engine'
        },
        {
          id: 'node-602',
          stage: 'Exfiltration',
          name: 'Direct File Download',
          risk: 90,
          probability: 85,
          impact: 'CRITICAL',
          affectedAsset: 'Customer PII Archives',
          reason: 'Files unencrypted at rest.',
          exploitability: 'Critical',
          recommendedControl: 'Enforce SSE-KMS Encryption & CSPM Scanning'
        }
      ]
    },
    {
      id: 'scenario-7',
      name: 'Custom Multi-Vector Supply Chain Attack',
      description: 'Compromised third-party NPM dependency injects backdoor into customer-facing web portal.',
      probability: 60,
      impact: 'HIGH',
      scenarioRisk: 82,
      criticalWeakPoint: 'Software Supply Chain Security & Dependency Audit',
      explanation: 'Lack of Software Bill of Materials (SBOM) and automated dependency vulnerability scanning.',
      nodes: [
        {
          id: 'node-701',
          stage: 'Dependency Poisoning',
          name: 'Malicious Dependency Injection',
          risk: 70,
          probability: 65,
          impact: 'HIGH',
          affectedAsset: 'CI/CD Build Pipeline',
          reason: 'Unpinned npm package versions.',
          exploitability: 'High',
          recommendedControl: 'Software Bill of Materials (SBOM) & Lockfile Verification'
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
      originOrgName: 'Demo Bank',
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

  public getActiveOrganization(): Organization {
    return this.organizations[this.activeOrgId] || this.organizations['org-1'];
  }
}

export const db = new DatabaseStore();
