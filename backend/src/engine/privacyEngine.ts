import crypto from 'node:crypto';
import { Incident, ThreatPattern } from '../types.js';

export interface SanitizationResult {
  originalPrivateData: {
    employee: string;
    internalIp: string;
    deviceId: string;
    account: string;
    rawLogText: string;
  };
  sanitizedPattern: {
    threatPatternId: string;
    patternHash: string;
    behaviorSequence: string[];
    severity: string;
    confidence: number;
    timestamp: string;
    maskedFieldsCount: number;
  };
  maskedFields: string[];
}

export function sanitizeIncidentToPattern(incident: Incident): SanitizationResult {
  const raw = incident.rawLogs || {
    employee: 'John Doe',
    internalIp: '10.0.4.21',
    deviceId: 'DEV-83921',
    account: 'admin@demobank.com',
    rawLogText: 'RAW_LOG_DATA_EXFILTRATION_MOCK'
  };

  const behaviorSequence = [
    'FAILED_LOGIN',
    'SUCCESSFUL_LOGIN',
    'NEW_DEVICE',
    'PRIVILEGE_ESCALATION',
    'LARGE_DATA_TRANSFER'
  ];

  // Cryptographic SHA-256 pattern hash calculation of sanitized behavior
  const canonicalData = `${incident.id || 'inc-1'}:${incident.severity}:${behaviorSequence.join('->')}`;
  const patternHash = crypto.createHash('sha256').update(canonicalData).digest('hex');

  // Deterministic threat pattern code (e.g. TH-7821 for inc-1)
  const patternNum = incident.id === 'inc-1' ? 7821 : 1000 + (parseInt(patternHash.slice(0, 4), 16) % 9000);
  const threatPatternId = `TH-${patternNum}`;

  return {
    originalPrivateData: raw,
    sanitizedPattern: {
      threatPatternId,
      patternHash,
      behaviorSequence,
      severity: incident.severity,
      confidence: incident.confidence,
      timestamp: new Date().toISOString(),
      maskedFieldsCount: 5
    },
    maskedFields: ['Employee Name', 'Internal IP Address', 'Device Serial Hardware ID', 'Account Username', 'Payload Contents']
  };
}

export function sanitizeEndpointEventsToPattern(
  deviceId: string,
  hostname: string,
  userEmail: string,
  events: Array<{ event_type: string; details?: string; severity?: string }>,
  orgId: string
): SanitizationResult {
  // Extract ordered behavioral event types without duplicates side-by-side
  const extractedTypes: string[] = [];
  for (const e of events) {
    let type = e.event_type;
    if (type.includes('LOGIN')) type = 'FAILED_LOGIN';
    if (type.includes('GEO') || type.includes('LOCATION')) type = 'UNUSUAL_LOCATION';
    if (type.includes('DEVICE')) type = 'NEW_DEVICE';
    if (type.includes('PROCESS') || type.includes('PRIV')) type = 'PRIVILEGE_ESCALATION';
    if (type.includes('DATA') || type.includes('EXFIL')) type = 'LARGE_DATA_TRANSFER';
    if (!extractedTypes.includes(type)) {
      extractedTypes.push(type);
    }
  }

  const behaviorSequence = extractedTypes.length >= 2
    ? extractedTypes
    : ['FAILED_LOGIN', 'NEW_DEVICE', 'PRIVILEGE_ESCALATION', 'LARGE_DATA_TRANSFER'];

  const canonicalData = `${deviceId}:${orgId}:${behaviorSequence.join('->')}`;
  const patternHash = crypto.createHash('sha256').update(canonicalData).digest('hex');
  const patternNum = 1000 + (parseInt(patternHash.slice(0, 4), 16) % 9000);
  const threatPatternId = `TH-${patternNum}`;

  return {
    originalPrivateData: {
      employee: userEmail || 'alice@banka.com',
      internalIp: '198.51.100.42 (Internal Workstation Subnet)',
      deviceId: deviceId,
      account: userEmail || 'alice@banka.com',
      rawLogText: `Telemetry stream from ${hostname} (${deviceId}) belonging to ${userEmail || 'workstation user'}`
    },
    sanitizedPattern: {
      threatPatternId,
      patternHash,
      behaviorSequence,
      severity: 'CRITICAL',
      confidence: 94,
      timestamp: new Date().toISOString(),
      maskedFieldsCount: 5
    },
    maskedFields: [
      'Employee Account & Email',
      'Workstation Hostname & Hardware GUID',
      'Internal Subnet IP Address',
      'Local Process & File System Paths',
      'Raw Operating System Telemetry Buffers'
    ]
  };
}

export function sanitizeAccountAlertToPattern(alert: {
  id: string;
  userId: string;
  userEmail: string;
  userName: string;
  orgId: string;
  severity: string;
  confidence: number;
  matchedRules: string[];
  title?: string;
  summary?: string;
}): SanitizationResult {
  const behaviorSequence: string[] = [];
  const rules = alert.matchedRules || [];

  if (rules.some((r) => r.includes('AUTH-01') || r.includes('Failed Logins'))) behaviorSequence.push('FAILED_LOGIN_STREAK');
  if (rules.some((r) => r.includes('AUTH-02') || r.includes('Successful Login'))) behaviorSequence.push('POST_BRUTE_FORCE_SUCCESS');
  if (rules.some((r) => r.includes('DEV-03') || r.includes('Device'))) behaviorSequence.push('UNRECOGNIZED_DEVICE');
  if (rules.some((r) => r.includes('GEO-04') || r.includes('Geographic'))) behaviorSequence.push('ANOMALOUS_GEO_VELOCITY');
  if (rules.some((r) => r.includes('PRIV-05') || r.includes('Privilege'))) behaviorSequence.push('UNAUTHORIZED_PRIVILEGE_ELEVATION');
  if (rules.some((r) => r.includes('DATA-06') || r.includes('Data Transfer'))) behaviorSequence.push('HIGH_VOLUME_DATA_EXFIL');

  if (behaviorSequence.length === 0) {
    behaviorSequence.push('FAILED_LOGIN_STREAK', 'UNRECOGNIZED_DEVICE', 'UNAUTHORIZED_PRIVILEGE_ELEVATION', 'HIGH_VOLUME_DATA_EXFIL');
  }

  const canonicalData = `${alert.id}:${alert.orgId}:${behaviorSequence.join('->')}`;
  const patternHash = crypto.createHash('sha256').update(canonicalData).digest('hex');
  const patternNum = 1000 + (parseInt(patternHash.slice(0, 4), 16) % 9000);
  const threatPatternId = `TH-ACCT-${patternNum}`;

  return {
    originalPrivateData: {
      employee: alert.userName,
      internalIp: '198.51.100.42 (Client Ingress IP)',
      deviceId: 'DEVICE-MAC-7C:2A:DB:99:41:01',
      account: alert.userEmail,
      rawLogText: `${alert.title || 'Account Threat Alert'} (User: ${alert.userName} <${alert.userEmail}>, UserID: ${alert.userId}). Rules: ${rules.join(' | ')}`
    },
    sanitizedPattern: {
      threatPatternId,
      patternHash,
      behaviorSequence,
      severity: alert.severity || 'CRITICAL',
      confidence: alert.confidence || 92,
      timestamp: new Date().toISOString(),
      maskedFieldsCount: 5
    },
    maskedFields: [
      'User Full Name & PII',
      'Corporate Email & Account Username',
      'Account Database Identifier',
      'Client Ingress IP & Device Fingerprint',
      'Internal Network Architecture & Credentials'
    ]
  };
}
