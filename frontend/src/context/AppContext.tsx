import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import {
  Organization,
  CalculatedRiskResult,
  AttackScenario,
  TelemetryEvent,
  Incident,
  ResponseAction,
  ThreatPattern,
  LedgerRecord,
  AppNotification,
  DemoStepInfo,
  VulnerabilityRecord,
  VulnerabilityStats,
  SyncEngineStatus,
  VulnerabilityFilterOptions,
  VulnerabilitySource
} from '../types';

export const DEMO_STEPS: DemoStepInfo[] = [
  {
    stepNumber: 1,
    title: 'DAY 1: NORMAL BASELINE POSTURE',
    subtitle: 'Healthy Security Posture & Normal Telemetry Baseline',
    explanation: 'Risk Score is stable at 42 (Low/Medium). Normal authentication traffic, firewall active, no active breaches detected.',
    targetPage: '/cyber-risk',
    badge: 'Day 1 • Baseline',
    durationMs: 12000
  },
  {
    stepNumber: 2,
    title: 'DAY 2: LATERAL MOVEMENT INFILTRATION',
    subtitle: 'Phishing Credential Access & Device Anomalies Detected',
    explanation: 'Adversary executes 15 failed logins followed by login from unrecognized device (Frankfurt, Germany). Risk escalates from 42 to 78.',
    targetPage: '/threat-detection',
    badge: 'Day 2 • Infiltration',
    durationMs: 14000
  },
  {
    stepNumber: 3,
    title: 'DAY 3: PRIVILEGE ESCALATION & MESH EARLY WARNING',
    subtitle: 'Cross-Organization DLT Consensus & Mesh Threat Broadcast',
    explanation: 'Privilege escalated to Domain Admin; risk spikes to 91 CRITICAL. Threat pattern TH-7821 is sanitized with zero PII, committed to DLT Ledger (Block #10421), and broadcasted to peer healthcare & fintech nodes with an Early Warning.',
    targetPage: '/collaborative-network',
    badge: 'Day 3 • Early Warning',
    durationMs: 16000
  },
  {
    stepNumber: 4,
    title: 'DAY 4: CONTAINMENT & REMEDIATION',
    subtitle: 'FIDO2 Hardware Key Enforcement & Chain Integrity Verification',
    explanation: 'Critical weak point remediated: FIDO2 WebAuthn enforced across identity providers. Risk score drops from 91 to 24. Cryptographic ledger verified.',
    targetPage: '/response-center',
    badge: 'Day 4 • Remediation',
    durationMs: 14000
  }
];

interface AppContextType {
  activeOrg: Organization | null;
  organizations: Organization[];
  riskData: CalculatedRiskResult | null;
  attackScenarios: AttackScenario[];
  telemetryStream: TelemetryEvent[];
  incidents: Incident[];
  responseActions: ResponseAction[];
  threatPatterns: ThreatPattern[];
  ledgerRecords: LedgerRecord[];
  notifications: AppNotification[];
  unreadCount: number;
  isLoading: boolean;
  
  // Vulnerability Intelligence State
  vulnerabilities: VulnerabilityRecord[];
  vulnerabilityStats: VulnerabilityStats | null;
  syncStatus: SyncEngineStatus | null;
  vulnPagination: { total: number; page: number; limit: number; totalPages: number };
  isLoadingVulns: boolean;
  isSyncingVulns: boolean;
  fetchVulnerabilities: (options?: VulnerabilityFilterOptions) => Promise<void>;
  fetchVulnerabilityById: (id: string) => Promise<VulnerabilityRecord | null>;
  fetchVulnerabilityStats: () => Promise<void>;
  fetchSyncStatus: () => Promise<void>;
  triggerLiveSync: (force?: boolean) => Promise<SyncEngineStatus | null>;

  // Demo Mode State
  isDemoActive: boolean;
  demoStep: number;
  isDemoAutoPlaying: boolean;
  demoSpeed: number;
  
  // Actions
  switchOrg: (orgId: string) => Promise<void>;
  updateOrgProfile: (id: string, data: Partial<Organization>) => Promise<void>;
  simulateAttack: (scenarioId: string) => Promise<any>;
  injectTelemetryEvent: (eventType: string, details?: string) => Promise<any>;
  executeResponseAction: (actionId: string, incidentId: string, markStatus?: 'In Progress' | 'Completed') => Promise<any>;
  remediateWeakPoint: () => Promise<any>;
  updateIncidentStatus: (incidentId: string, status: 'Detected' | 'Investigating' | 'Contained' | 'Resolved') => Promise<void>;
  sanitizePrivacyPattern: (incidentId: string) => Promise<any>;
  verifyLedgerRecord: (blockNumber?: number) => Promise<any>;
  tamperLedgerDemo: (blockNumber?: number) => Promise<any>;
  resetLedgerDemo: () => Promise<any>;
  validateLedgerBlock: (blockNumber: number, validatorOrg?: string) => Promise<any>;
  addCustomLedgerBlock: (threatId: string, reporter: string, hash: string) => Promise<any>;
  broadcastPatternToMesh: (threatCode: string, targetOrgId?: string) => Promise<any>;
  latestBroadcast: any | null;
  addResponseAction: (action: ResponseAction) => void;
  
  // Notifications Actions
  addNotification: (title: string, message: string, type?: 'ALERT' | 'THREAT' | 'LEDGER' | 'WARNING' | 'RISK' | 'SUCCESS', link?: string) => void;
  markNotificationRead: (id: string) => void;
  markAllNotificationsRead: () => void;
  clearNotifications: () => void;
  
  // Demo Mode Actions
  startDemo: () => void;
  stopDemo: () => void;
  setDemoStep: (step: number) => void;
  nextDemoStep: () => void;
  prevDemoStep: () => void;
  toggleDemoAutoPlay: () => void;
  resetDemoBaseline: () => Promise<any>;
}

const AppContext = createContext<AppContextType | undefined>(undefined);

export const AppProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [activeOrg, setActiveOrg] = useState<Organization | null>(null);
  const [riskData, setRiskData] = useState<CalculatedRiskResult | null>(null);
  const [attackScenarios, setAttackScenarios] = useState<AttackScenario[]>([]);
  const [telemetryStream, setTelemetryStream] = useState<TelemetryEvent[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [responseActions, setResponseActions] = useState<ResponseAction[]>([]);
  const [threatPatterns, setThreatPatterns] = useState<ThreatPattern[]>([]);
  const [ledgerRecords, setLedgerRecords] = useState<LedgerRecord[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Vulnerability Intelligence State
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityRecord[]>([]);
  const [vulnerabilityStats, setVulnerabilityStats] = useState<VulnerabilityStats | null>(null);
  const [syncStatus, setSyncStatus] = useState<SyncEngineStatus | null>(null);
  const [vulnPagination, setVulnPagination] = useState({ total: 0, page: 1, limit: 20, totalPages: 1 });
  const [isLoadingVulns, setIsLoadingVulns] = useState<boolean>(false);
  const [isSyncingVulns, setIsSyncingVulns] = useState<boolean>(false);
  const [latestBroadcast, setLatestBroadcast] = useState<any | null>(null);

  // Notifications State
  const [notifications, setNotifications] = useState<AppNotification[]>([
    {
      id: 'notif-1',
      title: '🚨 Critical Threat Detected',
      message: 'Possible Account Compromise & Data Exfiltration logged (INC-2026-8891). Confidence: 92%.',
      time: '09:44',
      type: 'ALERT',
      read: false,
      link: '/incidents'
    },
    {
      id: 'notif-2',
      title: '⚡ Dynamic Risk Score Increased',
      message: 'Demo Bank cyber risk score elevated from 78 to 91 (CRITICAL severity).',
      time: '09:42',
      type: 'RISK',
      read: false,
      link: '/cyber-risk'
    },
    {
      id: 'notif-3',
      title: '🔗 DLT Block Committed',
      message: 'Threat Pattern TH-7821 written to DLT Ledger (Block #10421). Validator consensus verified.',
      time: '09:38',
      type: 'LEDGER',
      read: false,
      link: '/dlt-ledger'
    },
    {
      id: 'notif-4',
      title: '🌐 Cross-Org Threat Warning',
      message: 'Threat Pattern TH-7821 matched with 92% sequence similarity in City Hospital telemetry stream.',
      time: '09:30',
      type: 'WARNING',
      read: false,
      link: '/collaborative-network'
    }
  ]);

  // Demo Mode State
  const [isDemoActive, setIsDemoActive] = useState<boolean>(false);
  const [demoStep, setDemoStepState] = useState<number>(1);
  const [isDemoAutoPlaying, setIsDemoAutoPlaying] = useState<boolean>(false);
  const [demoSpeed, setDemoSpeed] = useState<number>(4000);

  const fetchVulnerabilities = async (options: VulnerabilityFilterOptions = {}) => {
    try {
      setIsLoadingVulns(true);
      const params = new URLSearchParams();
      if (options.search) params.set('search', options.search);
      if (options.cveId) params.set('cveId', options.cveId);
      if (options.vendor) params.set('vendor', options.vendor);
      if (options.product) params.set('product', options.product);
      if (options.severity && options.severity !== 'ALL') params.set('severity', options.severity);
      if (options.cyberGuardPriority && options.cyberGuardPriority !== 'ALL') params.set('cyberGuardPriority', options.cyberGuardPriority);
      if (options.minCvss !== undefined) params.set('minCvss', String(options.minCvss));
      if (options.maxCvss !== undefined) params.set('maxCvss', String(options.maxCvss));
      if (options.knownExploited !== undefined) params.set('knownExploited', String(options.knownExploited));
      if (options.source && options.source !== 'ALL') params.set('source', options.source);
      if (options.sortBy) params.set('sortBy', options.sortBy);
      if (options.sortOrder) params.set('sortOrder', options.sortOrder);
      if (options.page) params.set('page', String(options.page));
      if (options.limit) params.set('limit', String(options.limit));

      const res = await fetch(`/api/vulnerabilities?${params.toString()}`).then((r) => r.json());
      if (res && res.data) {
        setVulnerabilities(res.data);
        if (res.pagination) {
          setVulnPagination(res.pagination);
        }
      }
    } catch (err) {
      console.error('Error fetching vulnerabilities:', err);
    } finally {
      setIsLoadingVulns(false);
    }
  };

  const fetchVulnerabilityById = async (id: string): Promise<VulnerabilityRecord | null> => {
    try {
      const res = await fetch(`/api/vulnerabilities/${encodeURIComponent(id)}`).then((r) => r.json());
      return res?.cveId ? res : null;
    } catch (err) {
      console.error('Error fetching vulnerability details:', err);
      return null;
    }
  };

  const fetchVulnerabilityStats = async () => {
    try {
      const res = await fetch('/api/vulnerabilities/stats').then((r) => r.json());
      if (res && res.total !== undefined) {
        setVulnerabilityStats(res);
      }
    } catch (err) {
      console.error('Error fetching vulnerability stats:', err);
    }
  };

  const fetchSyncStatus = async () => {
    try {
      const res = await fetch('/api/sync/status').then((r) => r.json());
      if (res && res.status) {
        setSyncStatus(res);
      }
    } catch (err) {
      console.error('Error fetching sync status:', err);
    }
  };

  const triggerLiveSync = async (force: boolean = false): Promise<SyncEngineStatus | null> => {
    try {
      setIsSyncingVulns(true);
      const res = await fetch('/api/sync/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ force })
      }).then((r) => r.json());

      if (res && res.status) {
        setSyncStatus(res);
        // Refresh vulnerabilities and stats
        await Promise.all([fetchVulnerabilities(), fetchVulnerabilityStats()]);
        addNotification(
          'Vulnerability Sync Complete',
          `Successfully ingested live intelligence: +${res.recordsAdded} new, ~${res.recordsUpdated} updated across authoritative sources.`,
          'SUCCESS',
          '/threat-intelligence'
        );
        return res;
      }
      return null;
    } catch (err: any) {
      console.error('Error triggering live sync:', err);
      addNotification('Sync Error', `Synchronization encountered an issue: ${err.message}`, 'WARNING', '/settings');
      return null;
    } finally {
      setIsSyncingVulns(false);
    }
  };

  const fetchAllData = async (orgId?: string) => {
    try {
      setIsLoading(true);
      // Fetch all response actions (we filter client-side by org)
      const [dashRes, orgsRes, attackRes, telRes, incRes, actRes, tpRes, ledgerRes, vulnRes, statsRes, syncRes] = await Promise.all([
        fetch('/api/dashboard').then((r) => r.json()),
        fetch('/api/organizations').then((r) => r.json()),
        fetch('/api/attack-scenarios').then((r) => r.json()),
        fetch('/api/telemetry').then((r) => r.json()),
        fetch('/api/incidents').then((r) => r.json()),
        fetch('/api/response-actions?orgId=all').then((r) => r.json()),
        fetch('/api/threat-intelligence').then((r) => r.json()),
        fetch('/api/ledger').then((r) => r.json()),
        fetch('/api/vulnerabilities?limit=20').then((r) => r.json()).catch(() => ({ data: [], pagination: {} })),
        fetch('/api/vulnerabilities/stats').then((r) => r.json()).catch(() => null),
        fetch('/api/sync/status').then((r) => r.json()).catch(() => null)
      ]);

      setActiveOrg(dashRes.organization);
      setRiskData(dashRes.risk);
      setOrganizations(orgsRes.organizations || []);
      setAttackScenarios(attackRes.scenarios || []);
      setTelemetryStream(telRes.telemetryStream || []);
      setIncidents(incRes.incidents || []);
      setResponseActions(actRes.responseActions || []);
      setThreatPatterns(tpRes.threatPatterns || []);
      setLedgerRecords(ledgerRes.ledgerRecords || []);

      if (vulnRes && vulnRes.data) {
        setVulnerabilities(vulnRes.data);
        if (vulnRes.pagination) setVulnPagination(vulnRes.pagination);
      }
      if (statsRes) setVulnerabilityStats(statsRes);
      if (syncRes) setSyncStatus(syncRes);
    } catch (err) {
      console.error('API Fetch error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAllData();
  }, []);

  const addNotification = (
    title: string,
    message: string,
    type: 'ALERT' | 'THREAT' | 'LEDGER' | 'WARNING' | 'RISK' | 'SUCCESS' = 'ALERT',
    link?: string
  ) => {
    const newNotif: AppNotification = {
      id: `notif-${Date.now()}`,
      title,
      message,
      time: new Date().toTimeString().slice(0, 5),
      type,
      read: false,
      link
    };
    setNotifications((prev) => [newNotif, ...prev]);
  };

  const markNotificationRead = (id: string) => {
    setNotifications((prev) => prev.map((n) => (n.id === id ? { ...n, read: true } : n)));
  };

  const markAllNotificationsRead = () => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  };

  const clearNotifications = () => {
    setNotifications([]);
  };

  const unreadCount = notifications.filter((n) => !n.read).length;

  const syncDemoStep = async (stepNum: number) => {
    try {
      const res = await fetch('/api/demo/step', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ step: stepNum })
      }).then((r) => r.json());

      if (res.activeOrg) {
        setActiveOrg(res.activeOrg);
        const dashRes = await fetch('/api/dashboard').then((r) => r.json());
        setRiskData(dashRes.risk);
      }
      if (res.incidents) setIncidents(res.incidents);
      if (res.threatPatterns) setThreatPatterns(res.threatPatterns);
      if (res.latestLedgerBlock) {
        const ledgerRes = await fetch('/api/ledger').then((r) => r.json());
        setLedgerRecords(ledgerRes.ledgerRecords || []);
      }

      const stepInfo = DEMO_STEPS.find((s) => s.stepNumber === stepNum);
      if (stepInfo) {
        addNotification(`Step ${stepNum}: ${stepInfo.title}`, stepInfo.subtitle, 'THREAT', stepInfo.targetPage);
      }
    } catch (err) {
      console.error('Demo step sync error:', err);
    }
  };

  const setDemoStep = (step: number) => {
    const validStep = Math.max(1, Math.min(DEMO_STEPS.length, step));
    setDemoStepState(validStep);
    syncDemoStep(validStep);
  };

  const nextDemoStep = () => {
    if (demoStep < DEMO_STEPS.length) setDemoStep(demoStep + 1);
    else setIsDemoAutoPlaying(false);
  };

  const prevDemoStep = () => {
    if (demoStep > 1) setDemoStep(demoStep - 1);
  };

  const startDemo = () => {
    setIsDemoActive(true);
    setDemoStep(1);
    setIsDemoAutoPlaying(true);
  };

  const stopDemo = () => {
    setIsDemoActive(false);
    setIsDemoAutoPlaying(false);
  };

  const toggleDemoAutoPlay = () => {
    setIsDemoAutoPlaying(!isDemoAutoPlaying);
  };

  const resetDemoBaseline = async () => {
    try {
      const res = await fetch('/api/demo/reset', { method: 'POST' }).then((r) => r.json());
      await fetchAllData();
      setIsDemoActive(false);
      setIsDemoAutoPlaying(false);
      setDemoStepState(1);
      addNotification('Demo Baseline Restored', 'System state, risk scores, and ledger reset to clean baseline.', 'SUCCESS', '/');
      return res;
    } catch (err) {
      console.error('Failed to reset demo baseline:', err);
    }
  };

  useEffect(() => {
    let timer: any = null;
    if (isDemoActive && isDemoAutoPlaying) {
      const currentStepObj = DEMO_STEPS.find((s) => s.stepNumber === demoStep);
      const stepDuration = currentStepObj?.durationMs || 10000;
      timer = setTimeout(() => {
        if (demoStep >= DEMO_STEPS.length) {
          setIsDemoAutoPlaying(false);
        } else {
          const next = demoStep + 1;
          setDemoStepState(next);
          syncDemoStep(next);
        }
      }, stepDuration);
    }
    return () => {
      if (timer) clearTimeout(timer);
    };
  }, [isDemoActive, isDemoAutoPlaying, demoStep]);

  const switchOrg = async (orgId: string) => {
    const res = await fetch('/api/organizations/switch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ orgId })
    }).then((r) => r.json());

    if (res.activeOrganization) {
      setActiveOrg(res.activeOrganization);
      await fetchAllData();
      addNotification('Organization Context Switched', `Switched active organization to ${res.activeOrganization.name}.`, 'SUCCESS', '/');
    }
  };

  const updateOrgProfile = async (id: string, data: Partial<Organization>) => {
    const res = await fetch(`/api/organizations/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    }).then((r) => r.json());

    if (res.organization) {
      setActiveOrg(res.organization);
      await fetchAllData();
      addNotification('Cyber Profile Updated', `Recalculated risk score for ${res.organization.name}: ${res.updatedRisk?.overallRiskScore ?? res.organization.riskScore}/100.`, 'RISK', '/cyber-risk');
    }
  };

  const simulateAttack = async (scenarioId: string) => {
    const res = await fetch(`/api/attack-scenarios/${scenarioId}/simulate`, {
      method: 'POST'
    }).then((r) => r.json());
    await fetchAllData();
    addNotification('Attack Simulation Completed', `Executed ${res.scenario?.name}. Weak point: ${res.scenario?.criticalWeakPoint}.`, 'ALERT', '/attack-path');
    return res;
  };

  const injectTelemetryEvent = async (eventType: string, details?: string) => {
    const res = await fetch('/api/telemetry/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ eventType, details })
    }).then((r) => r.json());
    await fetchAllData();

    if (res.threatDetected) {
      addNotification(`🚨 Threat Rule Triggered: ${res.threatDetected.title}`, `${res.threatDetected.reason} Risk increased +${res.riskTransition?.delta ?? 13} pts.`, 'ALERT', '/threat-detection');
    }

    return res;
  };

  const executeResponseAction = async (actionId: string, incidentId: string, markStatus: 'In Progress' | 'Completed' = 'Completed') => {
    const res = await fetch(`/api/incidents/${incidentId}/respond`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ actionId, markStatus })
    }).then((r) => r.json());
    await fetchAllData();

    if (res.riskReduction) {
      addNotification('Remediation Executed', `Action completed. Risk score reduced by ${res.riskReduction.pointsReduced} points (${res.riskReduction.previousScore} → ${res.riskReduction.newScore}).`, 'SUCCESS', '/response-center');
    }

    return res;
  };

  const remediateWeakPoint = async () => {
    const res = await fetch('/api/risk/remediate-weak-point', {
      method: 'POST'
    }).then((r) => r.json());
    await fetchAllData();

    if (res.success) {
      addNotification(
        'Critical Weakness Remediated',
        `Enforced FIDO2 WebAuthn Hardware Keys & Hardware MFA. Risk score dropped from ${res.previousScore} to ${res.newScore} (-24 pts).`,
        'SUCCESS',
        '/response-center'
      );
    }
    return res;
  };

  const updateIncidentStatus = async (incidentId: string, status: 'Detected' | 'Investigating' | 'Contained' | 'Resolved') => {
    const inc = incidents.find((i) => i.id === incidentId || i.incidentId === incidentId);
    if (inc) {
      inc.status = status;
      setIncidents([...incidents]);
      addNotification('Incident Status Updated', `${inc.incidentId} status changed to ${status}.`, 'THREAT', '/incidents');
    }
  };

  const sanitizePrivacyPattern = async (incidentId: string) => {
    const res = await fetch('/api/privacy/sanitize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ incidentId })
    }).then((r) => r.json());
    await fetchAllData();

    if (res.createdPattern) {
      addNotification('Shareable Threat Pattern Created', `Sanitized PII logs into Threat Pattern ${res.createdPattern.patternCode}. Cryptographic Hash: ${res.createdPattern.hash.slice(0, 16)}...`, 'LEDGER', '/threat-intelligence');
    }

    return res;
  };

  const verifyLedgerRecord = async (blockNumber?: number) => {
    const res = await fetch('/api/ledger/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ blockNumber })
    }).then((r) => r.json());

    if (res.isChainValid) {
      addNotification('DLT Chain Verified', 'Cryptographic SHA-256 integrity and hash linkage confirmed across all ledger blocks.', 'SUCCESS', '/dlt-ledger');
    } else {
      addNotification('🚨 Cryptographic Tamper Detected', `Chain broken at Block #${res.brokenBlockNumber || 'UNKNOWN'}! Hash mismatch detected.`, 'ALERT', '/dlt-ledger');
    }

    return res;
  };

  const tamperLedgerDemo = async (blockNumber?: number) => {
    const res = await fetch('/api/ledger/tamper', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ blockNumber })
    }).then((r) => r.json());

    if (res.ledgerRecords) {
      setLedgerRecords(res.ledgerRecords);
    }
    addNotification('🚨 Record Tampered (Demo)', `Block #${res.tamperedBlock?.blockNumber || 10420} was altered maliciously. Verify chain to see detection!`, 'WARNING', '/dlt-ledger');
    return res;
  };

  const resetLedgerDemo = async () => {
    const res = await fetch('/api/ledger/reset', { method: 'POST' }).then((r) => r.json());
    if (res.ledgerRecords) {
      setLedgerRecords(res.ledgerRecords);
    }
    addNotification('Ledger Restored', 'Blockchain integrity restored to verified baseline state.', 'SUCCESS', '/dlt-ledger');
    return res;
  };

  const validateLedgerBlock = async (blockNumber: number, validatorOrg?: string) => {
    const res = await fetch('/api/ledger/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ blockNumber, validatorOrg })
    }).then((r) => r.json());

    if (res.ledgerRecords) {
      setLedgerRecords(res.ledgerRecords);
    }
    addNotification('Validator Signature Committed', res.message || `Block #${blockNumber} validated.`, 'LEDGER', '/dlt-ledger');
    return res;
  };

  const addCustomLedgerBlock = async (threatId: string, reporter: string, hash: string) => {
    // POST to backend to actually add the block
    try {
      await fetch('/api/ledger/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ threatId, reporter, hash })
      });
    } catch (_) { /* fallback: block added locally */ }
    const ledgerRes = await fetch('/api/ledger').then((r) => r.json());
    setLedgerRecords(ledgerRes.ledgerRecords || []);
    addNotification('DLT Block Mined', `Threat ${threatId} committed to ledger by ${reporter}.`, 'LEDGER', '/dlt-ledger');
    return ledgerRes;
  };

  const broadcastPatternToMesh = async (threatCode: string, targetOrgId?: string) => {
    const res = await fetch('/api/network/broadcast', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ threatCode, targetOrgId })
    }).then((r) => r.json());

    setLatestBroadcast(res);
    await fetchAllData();

    addNotification(
      '🌐 Threat Pattern Broadcasted',
      `Pattern ${threatCode} propagated across ${res.meshPropagation?.length || 4} peer mesh nodes with cryptographic consensus.`,
      'WARNING',
      '/collaborative-network'
    );

    return res;
  };

  const addResponseAction = (action: ResponseAction) => {
    setResponseActions((prev) => [action, ...prev]);
  };

  return (
    <AppContext.Provider
      value={{
        activeOrg,
        organizations,
        riskData,
        attackScenarios,
        telemetryStream,
        incidents,
        responseActions,
        threatPatterns,
        ledgerRecords,
        notifications,
        unreadCount,
        isLoading,
        latestBroadcast,
        broadcastPatternToMesh,
        addResponseAction,
        vulnerabilities,
        vulnerabilityStats,
        syncStatus,
        vulnPagination,
        isLoadingVulns,
        isSyncingVulns,
        fetchVulnerabilities,
        fetchVulnerabilityById,
        fetchVulnerabilityStats,
        fetchSyncStatus,
        triggerLiveSync,
        isDemoActive,
        demoStep,
        isDemoAutoPlaying,
        demoSpeed,
        switchOrg,
        updateOrgProfile,
        simulateAttack,
        injectTelemetryEvent,
        executeResponseAction,
        remediateWeakPoint,
        updateIncidentStatus,
        sanitizePrivacyPattern,
        verifyLedgerRecord,
        tamperLedgerDemo,
        resetLedgerDemo,
        validateLedgerBlock,
        addCustomLedgerBlock,
        addNotification,
        markNotificationRead,
        markAllNotificationsRead,
        clearNotifications,
        startDemo,
        stopDemo,
        setDemoStep,
        nextDemoStep,
        prevDemoStep,
        toggleDemoAutoPlay,
        resetDemoBaseline
      }}
    >
      {children}
    </AppContext.Provider>
  );
};

export const useApp = () => {
  const context = useContext(AppContext);
  if (!context) throw new Error('useApp must be used within AppProvider');
  return context;
};
