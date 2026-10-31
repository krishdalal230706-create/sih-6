import React, { createContext, useContext, useState, useEffect, ReactNode, useCallback } from 'react';
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
  VulnerabilitySource,
  AuthUser,
  EndpointDevice
} from '../types';
import { useAuth } from './AuthContext';
import { api } from '../api/client';

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

  // Auth & Roles State (Re-exported from AuthContext)
  currentUser: AuthUser | null;
  token: string | null;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<{ success: boolean; error?: string; user?: AuthUser }>;
  logout: () => Promise<void>;
  resetPassword: (newPassword: string) => Promise<{ success: boolean; error?: string }>;
  quickDemoLogin: (email: string, password?: string) => Promise<void>;
  devices: EndpointDevice[];
  fetchDevices: () => Promise<void>;
}

const AppContext = createContext<AppContextType | undefined>(undefined);

export const AppProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const { currentUser, token, isAuthenticated, login, logout, resetPassword } = useAuth();

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

  const [devices, setDevices] = useState<EndpointDevice[]>([]);

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
      message: 'Bank A cyber risk score elevated from 78 to 91 (CRITICAL severity).',
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
    }
  ]);

  // Demo Mode State
  const [isDemoActive, setIsDemoActive] = useState<boolean>(false);
  const [demoStep, setDemoStepState] = useState<number>(1);
  const [isDemoAutoPlaying, setIsDemoAutoPlaying] = useState<boolean>(false);
  const [demoSpeed] = useState<number>(1);

  const addNotification = useCallback((
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
  }, []);

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

  const fetchVulnerabilities = async (options: VulnerabilityFilterOptions = {}) => {
    if (!isAuthenticated || currentUser?.role !== 'admin') return;
    try {
      setIsLoadingVulns(true);
      const queryParams = new URLSearchParams();
      if (options.source && options.source !== 'ALL') queryParams.append('source', options.source);
      if (options.severity && options.severity !== 'ALL') queryParams.append('severity', options.severity);
      if (options.search) queryParams.append('search', options.search);
      if (options.page) queryParams.append('page', options.page.toString());
      if (options.limit) queryParams.append('limit', options.limit.toString());
      if (options.knownExploited) queryParams.append('knownExploited', 'true');

      const res = await api.get<{ data: VulnerabilityRecord[]; pagination: any }>(
        `/api/vulnerabilities?${queryParams.toString()}`
      );
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
    if (!isAuthenticated || currentUser?.role !== 'admin') return null;
    try {
      const res = await api.get<VulnerabilityRecord>(`/api/vulnerabilities/${id}`);
      return res || null;
    } catch (err) {
      console.error('Error fetching vulnerability details:', err);
      return null;
    }
  };

  const fetchVulnerabilityStats = async () => {
    if (!isAuthenticated || currentUser?.role !== 'admin') return;
    try {
      const res = await api.get<VulnerabilityStats>('/api/vulnerabilities/stats');
      if (res && res.total !== undefined) {
        setVulnerabilityStats(res);
      }
    } catch (err) {
      console.error('Error fetching vulnerability stats:', err);
    }
  };

  const fetchSyncStatus = async () => {
    if (!isAuthenticated || currentUser?.role !== 'admin') return;
    try {
      const res = await api.get<SyncEngineStatus>('/api/sync/status');
      if (res && res.status) {
        setSyncStatus(res);
      }
    } catch (err) {
      console.error('Error fetching sync status:', err);
    }
  };

  const triggerLiveSync = async (force: boolean = false): Promise<SyncEngineStatus | null> => {
    if (!isAuthenticated || currentUser?.role !== 'admin') return null;
    try {
      setIsSyncingVulns(true);
      const res = await api.post<SyncEngineStatus>('/api/sync/run', { force });
      if (res && res.status) {
        setSyncStatus(res);
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

  const fetchDevices = useCallback(async () => {
    if (!token || currentUser?.role !== 'admin') return;
    try {
      const res = await api.get<{ devices: EndpointDevice[] }>('/api/devices').catch(() => null);
      if (res && res.devices) {
        setDevices(res.devices);
      }
    } catch (err) {
      console.error('Error fetching devices:', err);
    }
  }, [token, currentUser?.role]);

  const fetchAllData = useCallback(async () => {
    // Standard users and unauthenticated visitors MUST NOT fetch SOC data
    if (!isAuthenticated || currentUser?.role !== 'admin') {
      setIsLoading(false);
      return;
    }

    try {
      setIsLoading(true);
      const [dashRes, orgsRes, attackRes, telRes, incRes, actRes, tpRes, ledgerRes, vulnRes, statsRes, syncRes] = await Promise.all([
        api.get('/api/dashboard'),
        api.get('/api/organizations'),
        api.get('/api/attack-scenarios'),
        api.get('/api/telemetry'),
        api.get('/api/incidents'),
        api.get('/api/response-actions'),
        api.get('/api/threat-intelligence'),
        api.get('/api/ledger'),
        api.get('/api/vulnerabilities?limit=20').catch(() => ({ data: [], pagination: {} })),
        api.get('/api/vulnerabilities/stats').catch(() => null),
        api.get('/api/sync/status').catch(() => null)
      ]);

      if (dashRes && dashRes.organization) {
        setActiveOrg(dashRes.organization);
        setRiskData(dashRes.risk || null);
      }
      setOrganizations(orgsRes?.organizations || []);
      setAttackScenarios(attackRes?.scenarios || []);
      setTelemetryStream(telRes?.telemetryStream || []);
      setIncidents(incRes?.incidents || []);
      setResponseActions(actRes?.responseActions || []);
      setThreatPatterns(tpRes?.threatPatterns || []);
      setLedgerRecords(ledgerRes?.ledgerRecords || []);

      if (vulnRes && vulnRes.data) {
        setVulnerabilities(vulnRes.data);
        if (vulnRes.pagination) setVulnPagination(vulnRes.pagination);
      }
      if (statsRes) setVulnerabilityStats(statsRes);
      if (syncRes) setSyncStatus(syncRes);
    } catch (err) {
      console.error('Institutional SOC Fetch error:', err);
    } finally {
      setIsLoading(false);
    }
  }, [isAuthenticated, currentUser?.role]);

  // Scoped Data Fetching: Runs ONLY when an admin is actively authenticated
  useEffect(() => {
    if (isAuthenticated && currentUser?.role === 'admin') {
      fetchAllData();
      fetchDevices();
    } else {
      // Clear SOC state completely
      setActiveOrg(null);
      setRiskData(null);
      setOrganizations([]);
      setAttackScenarios([]);
      setTelemetryStream([]);
      setIncidents([]);
      setResponseActions([]);
      setThreatPatterns([]);
      setLedgerRecords([]);
      setVulnerabilities([]);
      setDevices([]);
      setIsLoading(false);
    }
  }, [isAuthenticated, currentUser?.role, currentUser?.orgId, fetchAllData, fetchDevices]);

  // Admin Real-Time WebSocket Connection
  useEffect(() => {
    if (!token || currentUser?.role !== 'admin') return;

    let ws: WebSocket | null = null;
    let reconnectTimer: any = null;
    let isCancelled = false;

    const connectWs = () => {
      const wsUrlBase = (import.meta as any).env?.VITE_WS_URL || 'ws://localhost:5000';
      const wsUrl = `${wsUrlBase}/ws/admin?token=${encodeURIComponent(token)}`;

      try {
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          console.log('🔌 [Admin WS] Real-time SOC channel connected for', currentUser.orgId);
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'DEVICE_CONNECTED' || data.type === 'DEVICE_OFFLINE') {
              fetchDevices();
            } else if (data.type === 'ACCOUNT_ALERT') {
              const alertMsg = data.alert?.title || 'Account threat activity detected';
              addNotification(
                `🚨 Hostile Account Attack: ${data.alert?.userName || 'User'}`,
                `${alertMsg} (${data.alert?.confidence || 88}% confidence).`,
                'ALERT',
                data.alert?.userId ? `/account-security/${data.alert.userId}` : '/account-security'
              );
              if (data.updatedOrgRisk && activeOrg) {
                setActiveOrg((prev) =>
                  prev
                    ? {
                        ...prev,
                        riskScore: data.updatedOrgRisk,
                        riskTrend: 'RISING'
                      }
                    : null
                );
              }
              fetchAllData();
            } else if (data.type === 'ACCOUNT_REMEDIATED') {
              addNotification(
                `✅ Account Secured: ${data.alert?.userName || 'User'}`,
                `Administrative fix applied. Account risk neutralized.`,
                'SUCCESS',
                data.alert?.userId ? `/account-security/${data.alert.userId}` : '/account-security'
              );
              if (data.updatedOrgRisk && activeOrg) {
                setActiveOrg((prev) =>
                  prev
                    ? {
                        ...prev,
                        riskScore: data.updatedOrgRisk,
                        riskTrend: 'FALLING'
                      }
                    : null
                );
              }
              fetchAllData();
            }
          } catch (e) {
            console.error('Error processing admin WS message:', e);
          }
        };

        ws.onclose = () => {
          if (!isCancelled) {
            reconnectTimer = setTimeout(connectWs, 3000);
          }
        };

        ws.onerror = () => {
          ws?.close();
        };
      } catch (err) {
        if (!isCancelled) {
          reconnectTimer = setTimeout(connectWs, 3000);
        }
      }
    };

    connectWs();

    const handleLogout = () => {
      isCancelled = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (ws) ws.close();
    };

    window.addEventListener('cyberguard:logout', handleLogout);

    return () => {
      isCancelled = true;
      window.removeEventListener('cyberguard:logout', handleLogout);
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (ws) ws.close();
    };
  }, [token, currentUser?.role, currentUser?.orgId, addNotification, fetchAllData, fetchDevices, activeOrg]);

  const quickDemoLogin = async (email: string, password?: string) => {
    await login(email, password || '');
  };

  const syncDemoStep = async (stepNum: number) => {
    try {
      const res = await api.post('/api/demo/step', { step: stepNum });
      if (res.activeOrg) {
        setActiveOrg(res.activeOrg);
        const dashRes = await api.get('/api/dashboard');
        setRiskData(dashRes.risk);
      }
      if (res.incidents) setIncidents(res.incidents);
      if (res.threatPatterns) setThreatPatterns(res.threatPatterns);
      if (res.latestLedgerBlock) {
        const ledgerRes = await api.get('/api/ledger');
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
      const res = await api.post('/api/demo/reset', {});
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
    if (orgId === activeOrg?.id) return;
    addNotification(
      'Multi-Tenant Scoped',
      'Institutional SOC console is scoped strictly to your authenticated organization.',
      'WARNING'
    );
  };

  const updateOrgProfile = async (id: string, data: Partial<Organization>) => {
    const res = await api.put(`/api/organizations/${id}`, data);
    if (res.organization) {
      setActiveOrg(res.organization);
      await fetchAllData();
      addNotification(
        'Cyber Profile Updated',
        `Recalculated risk score for ${res.organization.name}: ${res.updatedRisk?.overallRiskScore ?? res.organization.riskScore}/100.`,
        'RISK',
        '/cyber-risk'
      );
    }
  };

  const simulateAttack = async (scenarioId: string) => {
    const res = await api.post(`/api/attack-scenarios/${scenarioId}/simulate`);
    await fetchAllData();
    addNotification(
      'Attack Simulation Completed',
      `Executed ${res.scenario?.name}. Weak point: ${res.scenario?.criticalWeakPoint}.`,
      'ALERT',
      '/attack-path'
    );
    return res;
  };

  const injectTelemetryEvent = async (eventType: string, details?: string) => {
    const res = await api.post('/api/telemetry/simulate', { eventType, details });
    await fetchAllData();
    if (res.threatDetected) {
      addNotification(
        `🚨 Threat Rule Triggered: ${res.threatDetected.title}`,
        `${res.threatDetected.reason} Risk increased +${res.riskTransition?.delta ?? 13} pts.`,
        'ALERT',
        '/threat-detection'
      );
    }
    return res;
  };

  const executeResponseAction = async (actionId: string, incidentId: string, markStatus: 'In Progress' | 'Completed' = 'Completed') => {
    const res = await api.post(`/api/incidents/${incidentId}/respond`, { actionId, markStatus });
    await fetchAllData();
    if (res.riskReduction) {
      addNotification(
        'Remediation Executed',
        `Action completed. Risk score reduced by ${res.riskReduction.pointsReduced} points (${res.riskReduction.previousScore} → ${res.riskReduction.newScore}).`,
        'SUCCESS',
        '/response-center'
      );
    }
    return res;
  };

  const remediateWeakPoint = async () => {
    const res = await api.post('/api/risk/remediate-weak-point');
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
    const res = await api.post('/api/privacy/sanitize', { incidentId });
    await fetchAllData();
    if (res.createdPattern) {
      addNotification(
        'Shareable Threat Pattern Created',
        `Sanitized PII logs into Threat Pattern ${res.createdPattern.patternCode}. Cryptographic Hash: ${res.createdPattern.hash.slice(0, 16)}...`,
        'LEDGER',
        '/threat-intelligence'
      );
    }
    return res;
  };

  const verifyLedgerRecord = async (blockNumber?: number) => {
    const res = await api.post('/api/ledger/verify', { blockNumber });
    if (res.isChainValid) {
      addNotification('DLT Chain Verified', 'Cryptographic SHA-256 integrity and hash linkage confirmed across all ledger blocks.', 'SUCCESS', '/dlt-ledger');
    } else {
      addNotification('🚨 Cryptographic Tamper Detected', `Chain broken at Block #${res.brokenBlockNumber || 'UNKNOWN'}! Hash mismatch detected.`, 'ALERT', '/dlt-ledger');
    }
    return res;
  };

  const tamperLedgerDemo = async (blockNumber?: number) => {
    const res = await api.post('/api/ledger/tamper', { blockNumber });
    if (res.ledgerRecords) {
      setLedgerRecords(res.ledgerRecords);
    }
    addNotification('🚨 Record Tampered (Demo)', `Block #${res.tamperedBlock?.blockNumber || 10420} was altered maliciously. Verify chain to see detection!`, 'WARNING', '/dlt-ledger');
    return res;
  };

  const resetLedgerDemo = async () => {
    const res = await api.post('/api/ledger/reset', {});
    if (res.ledgerRecords) {
      setLedgerRecords(res.ledgerRecords);
    }
    addNotification('Ledger Restored', 'Blockchain integrity restored to verified baseline state.', 'SUCCESS', '/dlt-ledger');
    return res;
  };

  const validateLedgerBlock = async (blockNumber: number, validatorOrg?: string) => {
    const res = await api.post('/api/ledger/validate', { blockNumber, validatorOrg });
    if (res.ledgerRecords) {
      setLedgerRecords(res.ledgerRecords);
    }
    addNotification('Validator Signature Committed', res.message || `Block #${blockNumber} validated.`, 'LEDGER', '/dlt-ledger');
    return res;
  };

  const addCustomLedgerBlock = async (threatId: string, reporter: string, hash: string) => {
    try {
      await api.post('/api/ledger/add', { threatId, reporter, hash });
    } catch (_) { /* fallback */ }
    const ledgerRes = await api.get('/api/ledger');
    setLedgerRecords(ledgerRes.ledgerRecords || []);
    addNotification('DLT Block Mined', `Threat ${threatId} committed to ledger by ${reporter}.`, 'LEDGER', '/dlt-ledger');
    return ledgerRes;
  };

  const broadcastPatternToMesh = async (threatCode: string, targetOrgId?: string) => {
    const res = await api.post('/api/network/broadcast', { threatCode, targetOrgId });
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
        resetDemoBaseline,
        currentUser,
        token,
        isAuthenticated,
        login,
        logout,
        resetPassword,
        quickDemoLogin,
        devices,
        fetchDevices
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
