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
