export interface RiskBreakdown {
  authentication: number;
  networkSecurity: number;
  dataSecurity: number;
  endpointSecurity: number;
  userRisk: number;
}

export interface Organization {
  id: string;
  name: string;
  type: string;
  country?: string;
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

export interface BankingCategoryScores {
  authentication: number;
  coreBanking: number;
  paymentGateway: number;
  customerData: number;
  networkSecurity: number;
  endpointSecurity: number;
  atmSecurity: number;
  thirdParty: number;
  vulnerabilityExposure: number;
  incidentHistory: number;
}

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
  bankingCategoryScores?: BankingCategoryScores;
  highestRiskAssets?: {
    id: string;
    name: string;
    category: string;
    riskScore: number;
    securityStatus: string;
  }[];
  recommendations?: string[];
  explainableDeltas?: {
    factor: string;
    weight: string;
    score: number;
    weightedImpact: number;
    explanation: string;
  }[];
  contributors: {
    id: string;
    name: string;
    points: number;
    category: string;
    description: string;
  }[];
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
  probability: number;
  impact: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  scenarioRisk: number;
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
  incidentId: string;
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
  estimatedRiskReduction: number;
  status: 'Pending' | 'In Progress' | 'Completed';
  effort?: 'Low' | 'Medium' | 'High';
  estimatedTime?: string;
  isQuickWin?: boolean;
}

export interface ThreatPattern {
  id: string;
  patternCode: string;
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

export interface AppNotification {
  id: string;
  title: string;
  message: string;
  time: string;
  type: 'ALERT' | 'THREAT' | 'LEDGER' | 'WARNING' | 'RISK' | 'SUCCESS';
  read: boolean;
  link?: string;
}

export interface DemoStepInfo {
  stepNumber: number;
  title: string;
  subtitle: string;
  explanation: string;
  targetPage: string;
  badge: string;
  durationMs?: number;
}

export type VulnerabilitySeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
export type CyberGuardPriorityTier = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface VulnerabilityRecord {
  id: string;
  cveId: string;
  title: string;
  description: string;
  severity: VulnerabilitySeverity;
  cvssScore: number;
  cvssVector?: string;
  attackVector?: string;
  attackComplexity?: string;
  privilegesRequired?: string;
  userInteraction?: string;
  affectedVendor: string;
  affectedProduct: string;
  affectedVersions?: string;
  publishedDate: string;
  modifiedDate: string;
  exploitAvailable: boolean;
  knownExploited: boolean;
  source: string;
  references: string[];
  remediation?: string;
  lastUpdated: string;
  cyberGuardPriority: CyberGuardPriorityTier;
  cyberGuardScore: number;
  confidence: number;
}

export interface VulnerabilitySource {
  id: string;
  name: string;
  type: string;
  url: string;
  enabled: boolean;
  lastSyncAt: string | null;
  syncStatus: 'IDLE' | 'SYNCING' | 'SUCCESS' | 'ERROR';
  errorMessage?: string | null;
  recordsCount: number;
}

export interface SyncLog {
  id: string;
  sourceName: string;
  status: 'SUCCESS' | 'PARTIAL' | 'FAILED';
  recordsAdded: number;
  recordsUpdated: number;
  recordsSkipped: number;
  errorCount: number;
  errorDetails?: string | null;
  durationMs: number;
  createdAt: string;
}

export interface VulnerabilityFilterOptions {
  search?: string;
  cveId?: string;
  vendor?: string;
  product?: string;
  severity?: string;
  minCvss?: number;
  maxCvss?: number;
  knownExploited?: boolean;
  source?: string;
  cyberGuardPriority?: string;
  sortBy?: 'cyberGuardScore' | 'cvssScore' | 'publishedDate' | 'modifiedDate' | 'cveId';
  sortOrder?: 'asc' | 'desc';
  page?: number;
  limit?: number;
}

export interface VulnerabilityStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  knownExploited: number;
  exploitAvailable: number;
  avgCvssScore: number;
  avgCyberGuardScore: number;
  sourcesBreakdown: Record<string, number>;
  topVendors: { vendor: string; count: number }[];
  topProducts: { product: string; count: number }[];
  lastSyncTime: string | null;
  lastSuccessfulSyncTime: string | null;
  syncState: 'IDLE' | 'SYNCING' | 'LIVE' | 'DEMO_BASELINE' | 'ERROR';
}

export interface SyncEngineStatus {
  status: 'IDLE' | 'SYNCING' | 'SUCCESS' | 'ERROR';
  lastSyncTime: string | null;
  lastSuccessfulSyncTime: string | null;
  recordsAdded: number;
  recordsUpdated: number;
  recordsSkipped: number;
  errors: number;
  activeSources: string[];
  sources: VulnerabilitySource[];
  recentLogs: SyncLog[];
  isLive: boolean;
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

// Module 8: Endpoint Agent & Auth Types
export interface AuthUser {
  id: string;
  email: string;
  name: string;
  role: 'admin' | 'user';
  orgId: string;
  status?: 'active' | 'locked' | 'reset_required';
  mfaRequired?: boolean;
  privilegeLevel?: 'STANDARD' | 'ELEVATED' | 'ADMIN';
  mustReset?: boolean;
  createdAt?: string;
}

export interface LoginAttempt {
  id: string;
  user_id: string | null;
  email: string;
  org_id: string;
  success: number;
  ip_address: string;
  device_fingerprint: string;
  location: string;
  failure_reason: string | null;
  timestamp: string;
}

export interface AccountNotice {
  id: string;
  user_id: string;
  org_id: string;
  notice_type: string;
  message: string;
  created_at: string;
  acknowledged: number;
}

export interface AccountFactorContribution {
  id: string;
  category: 'Authentication' | 'Device Security' | 'Geographic Velocity' | 'Privilege' | 'Data Access';
  points: number;
  explanation: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
}

export interface AccountAlert {
  id: string;
  userId: string;
  userEmail: string;
  userName: string;
  orgId: string;
  status: 'New' | 'Investigating' | 'Remediated';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: number;
  title: string;
  summary: string;
  matchedRules: string[];
  factorContributions: AccountFactorContribution[];
  accountRiskScore: number;
  recommendedFixes: string[];
  timestamp: string;
  remediatedAt?: string | null;
  remediatedBy?: string | null;
}

export interface EndpointDevice {
  id: string;
  org_id: string;
  user_id: string;
  hostname: string;
  os: string;
  status: 'Healthy' | 'Suspicious' | 'Compromised' | 'Isolated' | 'Remediated' | 'Offline';
  risk: number;
  last_seen: string;
  enrolled_at: string;
  user_email?: string;
  user_name?: string;
}

export interface EndpointEvent {
  id: string;
  device_id: string;
  event_type: string;
  details: string;
  severity: string;
  timestamp: string;
}

export interface RemediationCommand {
  id: string;
  device_id: string;
  action: string;
  params: string;
  status: 'Pending' | 'Sent' | 'Executed' | 'Failed' | 'Rejected';
  issued_by: string;
  issued_at: string;
  expires_at: string;
  nonce: string;
  signature: string;
  result?: string | null;
  result_at?: string | null;
}

export interface AuditLogRecord {
  id: string;
  ts: string;
  actor: string;
  org_id: string;
  device_id: string | null;
  action: string;
  details: string;
  prev_hash: string;
  hash: string;
}

export interface MatchedRule {
  ruleId: string;
  name: string;
  description: string;
  severity: string;
  points: number;
}

export interface FactorContribution {
  id: string;
  category: string;
  points: number;
  explanation: string;
  severity: string;
}

export interface DeviceDetection {
  detected: boolean;
  deviceId: string;
  orgId: string;
  hostname: string;
  userEmail?: string;
  status: string;
  confidence: number;
  severity: string;
  title: string;
  summary: string;
  matchedRules: MatchedRule[];
  factorContributions: FactorContribution[];
  incidentId: string | null;
  timestamp: string;
}

export interface BankAsset {
  id: string;
  orgId: string;
  name: string;
  category: string;
  description: string;
  criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  ipOrIdentifier: string;
  technologyStack: string;
  ownerDepartment: string;
  securityStatus: 'HEALTHY' | 'DEGRADED' | 'AT_RISK' | 'COMPROMISED' | 'MAINTENANCE';
  associatedVulnsCount: number;
  lastAssessmentDate: string;
  riskScore: number;
  createdAt: string;
  updatedAt: string;
}

export interface BankSecurityEvent {
  id: string;
  orgId: string;
  affectedAssetId: string;
  affectedAssetName?: string;
  eventCategory: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  timestamp: string;
  description: string;
  detectionSource: string;
  investigationStatus: 'NEW' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED';
  recommendedAction: string;
}



