export interface RiskBreakdown {
  authentication: number;
  networkSecurity: number;
  dataSecurity: number;
  endpointSecurity: number;
  userRisk: number;
}

export interface RiskContributor {
  id: string;
  name: string;
  points: number; // e.g. +25
  category: string;
  description: string;
}

export interface Organization {
  id: string;
  name: string;
  type: string;
  usersCount: number;
  criticalSystems: number;
  internetFacingServices: number;
  authenticationMethods: string[];
  securityControls: string[];
  knownVulnerabilities: number;
  dataSensitivity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  previousIncidents: number;
  riskScore: number;
  riskTrend: 'RISING' | 'STABLE' | 'FALLING';
  lastUpdated: string;
  riskBreakdown: RiskBreakdown;
  activeThreatsCount: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export interface AttackNode {
  id: string;
  stage: string;
  name: string;
  risk: number;
  probability: number;
  impact: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  affectedAsset: string;
  reason: string;
  exploitability: 'Low' | 'Medium' | 'High' | 'Critical';
  recommendedControl: string;
}

export interface AttackScenario {
  id: string;
  name: string;
  description: string;
  nodes: AttackNode[];
  probability: number; // e.g. 78%
  impact: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  scenarioRisk: number; // e.g. 89
  criticalWeakPoint: string;
  explanation: string;
}

export interface TelemetryEvent {
  id: string;
  timestamp: string;
  eventType: 'FAILED_LOGIN' | 'SUCCESSFUL_LOGIN' | 'NEW_DEVICE' | 'UNUSUAL_LOCATION' | 'PRIVILEGE_ESCALATION' | 'LARGE_DATA_TRANSFER' | 'SUSPICIOUS_PROCESS' | 'UNUSUAL_ACCESS';
  sourceIp: string;
  user: string;
  deviceId: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  details: string;
}

export interface IncidentTimelineEvent {
  id: string;
  time: string;
  title: string;
  description: string;
  type: 'DETECTION' | 'RISK_INCREASE' | 'INVESTIGATION' | 'RESPONSE' | 'RESOLUTION';
}

export interface Incident {
  id: string;
  incidentId: string; // e.g. INC-2026-8891
  orgId: string;
  title: string;
  threatType: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'Detected' | 'Investigating' | 'Contained' | 'Resolved';
  detectionTime: string;
  affectedAsset: string;
  confidence: number;
  riskScore: number;
  description: string;
  timeline: IncidentTimelineEvent[];
  rawLogs?: {
    employee: string;
    internalIp: string;
    deviceId: string;
    account: string;
    rawLogText: string;
  };
}

export interface ResponseAction {
  id: string;
  incidentId: string;
  orgId: string;
  title: string;
  priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  reason: string;
  estimatedRiskReduction: number; // e.g. 24
  status: 'Pending' | 'In Progress' | 'Completed';
  effort?: 'Low' | 'Medium' | 'High';
  estimatedTime?: string;
  isQuickWin?: boolean;
}

export interface ThreatPattern {
  id: string;
  patternCode: string; // e.g. TH-7821
  originOrgId: string;
  originOrgName: string;
  patternSequence: string[];
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: number;
  status: 'Confirmed' | 'Unverified' | 'Mitigated';
  hash: string;
  createdAt: string;
  isShared: boolean;
}

export interface LedgerRecord {
  blockNumber: number;
  threatId: string;
  reporterOrg: string;
  validators: string[];
  status: 'CONFIRMED' | 'PENDING';
  timestamp: string;
  patternHash: string;
  previousHash: string;
  blockHash: string;
}

export interface AlignedEventBreakdown {
  eventA: string | null;
  eventB: string | null;
  status: 'MATCHED' | 'MISSING_IN_TARGET' | 'EXTRA_IN_TARGET';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  weight: number;
}

export interface CorrelationResult {
  targetOrgId: string;
  targetOrgName: string;
  matchedThreatCode: string;
  similarityPercentage: number;
  confidence: 'High' | 'Medium' | 'Low';
  warningMessage: string;
  sequenceComparison: {
    patternA: string[];
    patternB: string[];
    matchingEvents: string[];
    missingEvents: string[];
    alignedBreakdown: AlignedEventBreakdown[];
  };
  earlyWarningTriggered?: boolean;
}

export * from './types/vulnerability.js';
