import { VulnerabilityRecord } from '../types/vulnerability.js';
import { calculateCyberGuardRisk } from '../services/riskPrioritization.js';

const rawBaselineList: Omit<VulnerabilityRecord, 'id' | 'cyberGuardPriority' | 'cyberGuardScore' | 'confidence' | 'lastUpdated'>[] = [
  {
    cveId: 'CVE-2024-3400',
    title: 'Palo Alto Networks PAN-OS OS Command Injection',
    description: 'An arbitrary file creation vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software allows an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.',
    severity: 'CRITICAL',
    cvssScore: 10.0,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    attackVector: 'NETWORK',
    attackComplexity: 'LOW',
    privilegesRequired: 'NONE',
    userInteraction: 'NONE',
    affectedVendor: 'Palo Alto Networks',
    affectedProduct: 'PAN-OS',
    affectedVersions: 'PAN-OS 10.2, 11.0, 11.1',
    publishedDate: '2024-04-12T00:00:00Z',
    modifiedDate: '2024-04-16T18:30:00Z',
    exploitAvailable: true,
    knownExploited: true,
    source: 'CISA KEV + NVD',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2024-3400',
      'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      'https://security.paloaltonetworks.com/CVE-2024-3400'
    ],
    remediation: 'Upgrade to PAN-OS versions 10.2.9-h1, 11.0.4-h1, 11.1.2-h3, or apply Threat ID 95187 signature.'
  },
  {
    cveId: 'CVE-2024-21887',
    title: 'Ivanti Connect Secure Command Injection Vulnerability',
    description: 'A command injection vulnerability in web components of Ivanti Connect Secure (ICS) allows an authenticated administrator to send specially crafted requests and execute arbitrary commands on the appliance.',
    severity: 'CRITICAL',
    cvssScore: 9.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H',
    attackVector: 'NETWORK',
    attackComplexity: 'LOW',
    privilegesRequired: 'NONE',
    userInteraction: 'NONE',
    affectedVendor: 'Ivanti',
    affectedProduct: 'Connect Secure / Policy Secure Gateway',
    affectedVersions: '9.x, 22.x',
    publishedDate: '2024-01-12T00:00:00Z',
    modifiedDate: '2024-01-25T14:15:00Z',
    exploitAvailable: true,
    knownExploited: true,
    source: 'CISA KEV + NVD',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2024-21887',
      'https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-060a'
    ],
    remediation: 'Apply official Ivanti patch or XML mitigation file and run external integrity check tool.'
  },
  {
    cveId: 'CVE-2024-1709',
    title: 'ConnectWise ScreenConnect Authentication Bypass',
    description: 'ConnectWise ScreenConnect 23.9.7 and earlier contain an authentication bypass vulnerability using an alternate path or channel, allowing an attacker with network access to setup administrative accounts and execute arbitrary code.',
    severity: 'CRITICAL',
    cvssScore: 10.0,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    attackVector: 'NETWORK',
    attackComplexity: 'LOW',
    privilegesRequired: 'NONE',
    userInteraction: 'NONE',
    affectedVendor: 'ConnectWise',
    affectedProduct: 'ScreenConnect',
    affectedVersions: '<= 23.9.7',
    publishedDate: '2024-02-21T18:00:00Z',
    modifiedDate: '2024-02-27T12:00:00Z',
    exploitAvailable: true,
    knownExploited: true,
    source: 'CISA KEV + NVD',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2024-1709',
      'https://www.huntress.com/blog/slashandgrab-connectwise-screenconnect-vulnerability'
    ],
    remediation: 'Immediately upgrade ScreenConnect servers to version 23.9.8 or higher.'
  },
  {
    cveId: 'CVE-2024-6387',
    title: 'OpenSSH Server Remote Code Execution (regreSSHion)',
    description: 'A signal handler race condition in OpenSSH Server (sshd) allows unauthenticated remote code execution with root privileges on glibc-based Linux systems.',
    severity: 'HIGH',
    cvssScore: 8.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
    attackVector: 'NETWORK',
    attackComplexity: 'HIGH',
    privilegesRequired: 'NONE',
    userInteraction: 'NONE',
    affectedVendor: 'OpenBSD / Linux',
    affectedProduct: 'OpenSSH sshd',
    affectedVersions: '8.5p1 <= sshd < 9.8p1',
    publishedDate: '2024-07-01T08:00:00Z',
    modifiedDate: '2024-07-08T19:00:00Z',
    exploitAvailable: true,
    knownExploited: false,
    source: 'NVD + OSV',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2024-6387',
      'https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt'
    ],
    remediation: 'Update OpenSSH to version 9.8p1 or set LoginGraceTime 0 in sshd_config as immediate mitigation.'
  },
  {
    cveId: 'CVE-2024-27198',
    title: 'JetBrains TeamCity Authentication Bypass in Web Component',
    description: 'Authentication bypass vulnerability in JetBrains TeamCity server web component allowing unauthenticated attackers to gain administrative control over the CI/CD pipeline.',
    severity: 'CRITICAL',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    attackVector: 'NETWORK',
    attackComplexity: 'LOW',
    privilegesRequired: 'NONE',
    userInteraction: 'NONE',
    affectedVendor: 'JetBrains',
    affectedProduct: 'TeamCity Server',
    affectedVersions: '< 2023.11.4',
    publishedDate: '2024-03-04T12:00:00Z',
    modifiedDate: '2024-03-10T16:00:00Z',
    exploitAvailable: true,
    knownExploited: true,
    source: 'CISA KEV + NVD',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2024-27198',
      'https://blog.jetbrains.com/teamcity/2024/03/additional-critical-security-issues-affecting-teamcity-on-premises-cve-2024-27198-and-cve-2024-27199/'
    ],
    remediation: 'Upgrade to JetBrains TeamCity 2023.11.4 or apply official security plugin.'
  },
  {
    cveId: 'CVE-2024-40766',
    title: 'SonicWall SonicOS Improper Access Control Vulnerability',
    description: 'An improper access control vulnerability in SonicWall SonicOS allows unauthorized resource access and, under certain conditions, causes the firewall appliance to crash or permit configuration manipulation.',
    severity: 'CRITICAL',
    cvssScore: 9.3,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    attackVector: 'NETWORK',
    attackComplexity: 'LOW',
    privilegesRequired: 'NONE',
    userInteraction: 'NONE',
    affectedVendor: 'SonicWall',
    affectedProduct: 'SonicOS (Gen 5, 6, 7 Devices)',
    affectedVersions: 'SonicOS 7.0.1-5035 and earlier',
    publishedDate: '2024-08-22T10:00:00Z',
    modifiedDate: '2024-09-06T14:30:00Z',
    exploitAvailable: true,
    knownExploited: true,
    source: 'CISA KEV + NVD',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2024-40766',
      'https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2024-0015'
    ],
    remediation: 'Update to patched SonicOS firmware releases and disable WAN management access.'
  },
  {
    cveId: 'CVE-2023-4966',
    title: 'Citrix Bleed Sensitive Information Disclosure',
    description: 'NetScaler ADC and NetScaler Gateway contain a buffer overflow flaw allowing unauthenticated remote extraction of active session tokens from device memory.',
    severity: 'CRITICAL',
    cvssScore: 9.4,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    attackVector: 'NETWORK',
    attackComplexity: 'LOW',
    privilegesRequired: 'NONE',
    userInteraction: 'NONE',
    affectedVendor: 'Citrix / Cloud Software Group',
    affectedProduct: 'NetScaler ADC & NetScaler Gateway',
    affectedVersions: '13.0, 13.1, 14.1',
    publishedDate: '2023-10-10T12:00:00Z',
    modifiedDate: '2023-11-21T18:00:00Z',
    exploitAvailable: true,
    knownExploited: true,
    source: 'CISA KEV + NVD',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2023-4966',
      'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a'
    ],
    remediation: 'Apply Citrix updates and terminate all existing AAA active and persistent user sessions.'
  },
  {
    cveId: 'CVE-2023-34362',
    title: 'Progress MOVEit Transfer SQL Injection Remote Code Execution',
    description: 'SQL injection vulnerability in the MOVEit Transfer web application that could allow an unauthenticated attacker to gain access to MOVEit Transfer database and execute arbitrary code.',
    severity: 'CRITICAL',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    attackVector: 'NETWORK',
    attackComplexity: 'LOW',
    privilegesRequired: 'NONE',
    userInteraction: 'NONE',
    affectedVendor: 'Progress Software',
    affectedProduct: 'MOVEit Transfer',
    affectedVersions: '2021.0, 2022.0, 2023.0',
    publishedDate: '2023-06-02T10:00:00Z',
    modifiedDate: '2023-07-15T15:00:00Z',
    exploitAvailable: true,
    knownExploited: true,
    source: 'CISA KEV + NVD',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2023-34362',
      'https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-31May2023'
    ],
    remediation: 'Apply vendor hotfixes and inspect environments for webshell indicators.'
  },
  {
    cveId: 'CVE-2024-23897',
    title: 'Jenkins CLI Arbitrary File Read Leading to RCE',
    description: 'Jenkins uses args4j parser in CLI command parsing which by default expands @ character followed by a file path, allowing unauthenticated attackers to read arbitrary files and escalate to RCE.',
    severity: 'CRITICAL',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    attackVector: 'NETWORK',
    attackComplexity: 'LOW',
    privilegesRequired: 'NONE',
    userInteraction: 'NONE',
    affectedVendor: 'Jenkins',
    affectedProduct: 'Jenkins Core Server',
    affectedVersions: '<= 2.441, LTS <= 2.426.2',
    publishedDate: '2024-01-24T18:00:00Z',
    modifiedDate: '2024-02-05T12:00:00Z',
    exploitAvailable: true,
    knownExploited: true,
    source: 'CISA KEV + GitHub Advisory',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2024-23897',
      'https://www.jenkins.io/security/advisory/2024-01-24/'
    ],
    remediation: 'Upgrade to Jenkins 2.442 or LTS 2.426.3, or disable CLI endpoint access.'
  },
  {
    cveId: 'CVE-2021-44228',
    title: 'Apache Log4j2 JNDI Remote Code Execution (Log4Shell)',
    description: 'Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints, allowing unauthenticated remote code execution.',
    severity: 'CRITICAL',
    cvssScore: 10.0,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    attackVector: 'NETWORK',
    attackComplexity: 'LOW',
    privilegesRequired: 'NONE',
    userInteraction: 'NONE',
    affectedVendor: 'Apache Software Foundation',
    affectedProduct: 'Log4j Core',
    affectedVersions: '2.0-beta9 <= 2.14.1',
    publishedDate: '2021-12-10T10:00:00Z',
    modifiedDate: '2023-04-17T11:00:00Z',
    exploitAvailable: true,
    knownExploited: true,
    source: 'CISA KEV + NVD + OSV',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2021-44228',
      'https://logging.apache.org/log4j/2.x/security.html'
    ],
    remediation: 'Upgrade all Apache Log4j dependencies to 2.17.1 or higher.'
  },
  {
    cveId: 'CVE-2024-21413',
    title: 'Microsoft Outlook Remote Code Execution (MonikerLink)',
    description: 'Microsoft Outlook Remote Code Execution Vulnerability allowing attackers to bypass Office Protected View and execute code via crafted file: links.',
    severity: 'CRITICAL',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    attackVector: 'NETWORK',
    attackComplexity: 'LOW',
    privilegesRequired: 'NONE',
    userInteraction: 'NONE',
    affectedVendor: 'Microsoft',
    affectedProduct: 'Microsoft 365 Apps / Office / Outlook',
    affectedVersions: 'Outlook 2016, 2019, LTSC 2021, M365 Apps',
    publishedDate: '2024-02-13T08:00:00Z',
    modifiedDate: '2024-03-01T15:00:00Z',
    exploitAvailable: true,
    knownExploited: true,
    source: 'CISA KEV + NVD',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2024-21413',
      'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413'
    ],
    remediation: 'Install Microsoft February 2024 security updates across all Office client installations.'
  },
  {
    cveId: 'CVE-2024-38856',
    title: 'Apache OFBiz Unauthenticated Remote Code Execution',
    description: 'Incorrect authorization vulnerability in Apache OFBiz allows unauthenticated remote attackers to execute arbitrary code on the server through overridden view-maps.',
    severity: 'CRITICAL',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    attackVector: 'NETWORK',
    attackComplexity: 'LOW',
    privilegesRequired: 'NONE',
    userInteraction: 'NONE',
    affectedVendor: 'Apache Software Foundation',
    affectedProduct: 'OFBiz Enterprise ERP',
    affectedVersions: '< 18.12.15',
    publishedDate: '2024-08-05T14:00:00Z',
    modifiedDate: '2024-08-20T10:00:00Z',
    exploitAvailable: true,
    knownExploited: true,
    source: 'CISA KEV + OSV',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2024-38856',
      'https://ofbiz.apache.org/security.html'
    ],
    remediation: 'Upgrade to Apache OFBiz 18.12.15 or newer.'
  }
];

export function getBaselineDemoVulnerabilities(): VulnerabilityRecord[] {
  return rawBaselineList.map((item, idx) => {
    const risk = calculateCyberGuardRisk({
      cvssScore: item.cvssScore,
      knownExploited: item.knownExploited,
      exploitAvailable: item.exploitAvailable,
      attackVector: item.attackVector,
      attackComplexity: item.attackComplexity,
      privilegesRequired: item.privilegesRequired,
      userInteraction: item.userInteraction,
      publishedDate: item.publishedDate,
      modifiedDate: item.modifiedDate,
      source: item.source
    });

    return {
      ...item,
      id: `vuln-base-${idx + 1}`,
      cyberGuardScore: risk.cyberGuardScore,
      cyberGuardPriority: risk.cyberGuardPriority,
      confidence: risk.confidence,
      lastUpdated: new Date().toISOString()
    };
  });
}
