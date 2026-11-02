import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Lock,
  KeyRound,
  Globe,
  AlertTriangle,
  AlertCircle,
  CheckCircle2,
  XCircle,
  Bell,
  RefreshCw,
  Check,
  LogOut,
  Building2,
  Shield,
  Play,
  Send,
  HelpCircle,
  Eye,
  EyeOff,
  Smartphone,
  ChevronDown,
  ChevronUp,
  Clock,
  Laptop
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { api } from '../api/client';
import { LoginAttempt, AccountNotice } from '../types';

interface UserReport {
  id: string;
  title: string;
  summary: string;
  status: 'New' | 'Investigating' | 'Resolved' | 'Remediated';
  timestamp: string;
  remediatedAt?: string | null;
}

interface MyAccountData {
  user: {
    id: string;
    email: string;
    name: string;
    role: 'admin' | 'user';
    orgId: string;
    orgName?: string;
    status: 'active' | 'locked' | 'reset_required' | 'pending';
    mfaRequired: boolean;
    privilegeLevel: 'STANDARD' | 'ELEVATED' | 'ADMIN';
    mustReset: boolean;
    createdAt?: string;
  };
  recentSignIns: LoginAttempt[];
  notices: AccountNotice[];
  reports: UserReport[];
  activeSessionsCount: number;
}

export const MyAccount: React.FC = () => {
  const { currentUser, token, logout, resetPassword } = useAuth();

  const [accountData, setAccountData] = useState<MyAccountData | null>(null);
  const [loading, setLoading] = useState(true);
  const [isDemoMode, setIsDemoMode] = useState(false);

  // Password reset form
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [passwordSuccess, setPasswordSuccess] = useState<string | null>(null);
  const [isSubmittingPassword, setIsSubmittingPassword] = useState(false);

  // Self-report form
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const [reportDetails, setReportDetails] = useState('');
  const [isSubmittingReport, setIsSubmittingReport] = useState(false);
  const [reportSuccessMessage, setReportSuccessMessage] = useState<string | null>(null);

  // "This wasn't me" reporting
  const [reportingAttemptId, setReportingAttemptId] = useState<string | null>(null);
  const [reportedAttemptIds, setReportedAttemptIds] = useState<Set<string>>(new Set());

  // MFA Modal state
  const [isMfaModalOpen, setIsMfaModalOpen] = useState(false);
  const [mfaCode, setMfaCode] = useState('');
  const [simulatedMfaCode, setSimulatedMfaCode] = useState<string | null>(null);
  const [mfaError, setMfaError] = useState<string | null>(null);
  const [isTogglingMfa, setIsTogglingMfa] = useState(false);

  // Active Sessions state
  const [isRevokingSessions, setIsRevokingSessions] = useState(false);
  const [sessionSuccessMsg, setSessionSuccessMsg] = useState<string | null>(null);

  // Demo Tools Collapsible
  const [isDemoToolsOpen, setIsDemoToolsOpen] = useState(false);
  const [isSimulating, setIsSimulating] = useState(false);
  const [simulationMessage, setSimulationMessage] = useState<string | null>(null);

  // Unified Date Formatter
  const formatDate = (isoString?: string): string => {
    if (!isoString) return '—';
    try {
      const d = new Date(isoString);
      if (isNaN(d.getTime())) return isoString;
      return d.toLocaleString('en-US', {
        month: 'short',
        day: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: true
      });
    } catch {
      return isoString;
    }
  };

  // Safe Location Formatter (Replaces 127.0.0.1 or local IPs with "Local network (demo)")
  const formatLocation = (ip: string, loc?: string): string => {
    if (ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.16.')) {
      return 'Local network (demo)';
    }
    return loc || 'Local network (demo)';
  };

  // Password Strength Calculator
  const calculatePasswordStrength = (pass: string): { score: number; label: string; color: string } => {
    if (!pass) return { score: 0, label: '', color: 'bg-slate-700' };
    let score = 0;
    if (pass.length >= 8) score += 1;
    if (/[A-Z]/.test(pass) && /[a-z]/.test(pass)) score += 1;
    if (/\d/.test(pass)) score += 1;
    if (/[^A-Za-z0-9]/.test(pass)) score += 1;

    switch (score) {
      case 1:
        return { score: 25, label: 'Weak (add numbers & letters)', color: 'bg-rose-500' };
      case 2:
        return { score: 50, label: 'Fair (add special character)', color: 'bg-amber-500' };
      case 3:
        return { score: 75, label: 'Good (strong protection)', color: 'bg-cyan-500' };
      case 4:
        return { score: 100, label: 'Strong (production grade)', color: 'bg-emerald-500' };
      default:
        return { score: 10, label: 'Too short', color: 'bg-rose-600' };
    }
  };

  const fetchAccountDetails = useCallback(async () => {
    if (!token) return;
    try {
      setLoading(true);
      const data = await api.get<MyAccountData>('/api/auth/my-account');
      if (data && data.user) {
        setAccountData(data);
      }
    } catch (err: any) {
      console.error('Error fetching account data:', err);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchAccountDetails();
  }, [fetchAccountDetails]);

  // Check DEMO_MODE
  useEffect(() => {
    api.get('/api/auth/demo-users')
      .then((res) => { if (res) setIsDemoMode(true); })
      .catch(() => { setIsDemoMode(false); });
  }, []);

  // WebSocket Live Updates
  useEffect(() => {
    if (!token || !currentUser) return;

    let ws: WebSocket | null = null;
    let reconnectTimer: any = null;
    let isCancelled = false;

    const connectUserWs = () => {
      const defaultWsHost = typeof window !== 'undefined' ? `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.hostname}:5000` : 'ws://localhost:5000';
      const wsUrlBase = (import.meta as any).env?.VITE_WS_URL || defaultWsHost;
      const wsUrl = `${wsUrlBase}/ws/user?token=${encodeURIComponent(token)}`;

      try {
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          console.log('🔌 [User WS] Live notification channel connected for', currentUser.email);
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            console.log('🔔 [User WS] Received live event:', data.type);
            fetchAccountDetails();
          } catch (e) {
            console.error('Error processing user WS event:', e);
          }
        };

        ws.onclose = () => {
          if (!isCancelled) {
            reconnectTimer = setTimeout(connectUserWs, 3000);
          }
        };

        ws.onerror = () => {
          ws?.close();
        };
      } catch (err) {
        if (!isCancelled) {
          reconnectTimer = setTimeout(connectUserWs, 3000);
        }
      }
    };

    connectUserWs();

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
  }, [token, currentUser, fetchAccountDetails]);

  // Card 2: Calculate User Security Score & Actionable Tips
  const calculateSecurityScore = () => {
    const user = accountData?.user || currentUser;
    if (!user) return { score: 70, tips: [] };

    let score = 0;
    const tips: { id: string; title: string; desc: string; passed: boolean }[] = [];

    // Signal 1: MFA Status (25 pts)
    const mfaOn = user.mfaRequired;
    if (mfaOn) {
      score += 25;
      tips.push({
        id: 'mfa',
        title: 'Multi-Factor Authentication',
        desc: 'MFA is enabled on your credentials, blocking automated credential stuffing.',
        passed: true
      });
    } else {
      tips.push({
        id: 'mfa',
        title: 'Multi-Factor Authentication',
        desc: 'Enable MFA below to protect your workplace account against credential stuffing.',
        passed: false
      });
    }

    // Signal 2: Password Status (25 pts)
    const isReset = user.status === 'reset_required' || user.mustReset;
    if (!isReset) {
      score += 25;
      tips.push({
        id: 'pwd',
        title: 'Credential Freshness',
        desc: 'Your workplace password is in good standing and meets institutional requirements.',
        passed: true
      });
    } else {
      tips.push({
        id: 'pwd',
        title: 'Mandatory Password Reset Required',
        desc: 'An administrator flagged your account. Set a new password below immediately.',
        passed: false
      });
    }

    // Signal 3: Recent Failed Logins (25 pts)
    const signIns = accountData?.recentSignIns || [];
    const failedRecent = signIns.filter(s => s.success === 0).length;
    if (failedRecent === 0) {
      score += 25;
      tips.push({
        id: 'failed',
        title: 'Zero Authentication Failures',
        desc: 'No suspicious failed login streaks detected in your recent access logs.',
        passed: true
      });
    } else {
      const penalty = Math.min(25, failedRecent * 8);
      score += Math.max(0, 25 - penalty);
      tips.push({
        id: 'failed',
        title: `${failedRecent} Failed Sign-In Attempt(s)`,
        desc: 'Review sign-in history below and use "This wasn\'t me" for any unrecognized attempts.',
        passed: false
      });
    }

    // Signal 4: Active Session Hygiene (25 pts)
    const sessionCount = accountData?.activeSessionsCount || 1;
    if (sessionCount <= 2) {
      score += 25;
      tips.push({
        id: 'sessions',
        title: 'Session Footprint',
        desc: `You currently have ${sessionCount} active session. No sprawling token exposure.`,
        passed: true
      });
    } else {
      score += 15;
      tips.push({
        id: 'sessions',
        title: `${sessionCount} Active Sessions`,
        desc: 'Sign out unused devices below to minimize session token attack surface.',
        passed: false
      });
    }

    return { score: Math.min(100, score), tips };
  };

  // Password reset submit
  const handlePasswordReset = async (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordError(null);
    setPasswordSuccess(null);

    if (newPassword.length < 8 || !/(?=.*[A-Za-z])(?=.*\d)/.test(newPassword)) {
      setPasswordError('Password must be at least 8 characters long and contain both letters and numbers.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setPasswordError('Passwords do not match.');
      return;
    }

    setIsSubmittingPassword(true);
    const res = await resetPassword(newPassword);
    setIsSubmittingPassword(false);

    if (res.success) {
      setPasswordSuccess('Password successfully updated. Security status restored.');
      setNewPassword('');
      setConfirmPassword('');
      await fetchAccountDetails();
    } else {
      setPasswordError(res.error || 'Failed to update credentials.');
    }
  };

  // Dismiss notice
  const handleDismissNotice = async (noticeId: string) => {
    try {
      await api.post(`/api/auth/notices/${noticeId}/dismiss`, {});
      if (accountData) {
        setAccountData({
          ...accountData,
          notices: accountData.notices.filter((n) => n.id !== noticeId)
        });
      }
    } catch (err) {
      console.error('Error dismissing notice:', err);
    }
  };

  // Report Suspicious Activity Form Submit
  const handleReportSuspicious = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmittingReport(true);
    setReportSuccessMessage(null);

    try {
      const res = await api.post<{ success: boolean; message: string }>('/api/auth/report-suspicious', {
        details: reportDetails
      });
      setIsSubmittingReport(false);
      setReportDetails('');
      setIsReportModalOpen(false);
      setReportSuccessMessage(res.message || 'Suspicious activity report logged with SOC administration.');
      await fetchAccountDetails();
    } catch (err: any) {
      setIsSubmittingReport(false);
      alert(err.message || 'Failed to submit security report.');
    }
  };

  // "This Wasn't Me" click handler on sign-in row
  const handleThisWasntMe = async (attempt: LoginAttempt) => {
    setReportingAttemptId(attempt.id);
    try {
      const details = `Unrecognized sign-in attempt from IP ${attempt.ip_address} (${formatLocation(attempt.ip_address, attempt.location)}) on ${formatDate(attempt.timestamp)}. User explicitly clicked "This wasn't me".`;
      const res = await api.post<{ success: boolean; message: string }>('/api/auth/report-suspicious', {
        details
      });

      setReportedAttemptIds(prev => new Set(prev).add(attempt.id));
      setReportSuccessMessage(`Incident reported to your organization SOC administrator: ${res.message}`);
      await fetchAccountDetails();
    } catch (err: any) {
      alert(err.message || 'Failed to dispatch security report.');
    } finally {
      setReportingAttemptId(null);
    }
  };

  // Sign out other devices
  const handleSignOutOtherDevices = async () => {
    setIsRevokingSessions(true);
    setSessionSuccessMsg(null);
    try {
      const res = await api.post<{ success: boolean; message: string }>('/api/auth/sign-out-other-devices', {});
      setIsRevokingSessions(false);
      setSessionSuccessMsg(res.message || 'All other active sessions have been signed out.');
      await fetchAccountDetails();
    } catch (err: any) {
      setIsRevokingSessions(false);
      alert(err.message || 'Failed to sign out other devices.');
    }
  };

  // Open MFA Toggle Modal
  const handleOpenMfaModal = async () => {
    setIsMfaModalOpen(true);
    setMfaError(null);
    setMfaCode('');

    const user = accountData?.user || currentUser;
    if (!user?.mfaRequired) {
      // Request verification code for setup
      try {
        const res = await api.post<{ success: boolean; demoCode?: string }>('/api/auth/mfa/request', {});
        if (res.demoCode) {
          setSimulatedMfaCode(res.demoCode);
        }
      } catch (err) {
        console.error('Failed to request MFA code:', err);
      }
    }
  };

  // Confirm MFA Toggle
  const handleConfirmMfaToggle = async () => {
    const user = accountData?.user || currentUser;
    const willEnable = !user?.mfaRequired;
    setIsTogglingMfa(true);
    setMfaError(null);

    try {
      const res = await api.post<{ success: boolean; mfaRequired: boolean; message: string }>('/api/auth/mfa/toggle', {
        enable: willEnable,
        code: mfaCode.trim()
      });
      setIsTogglingMfa(false);
      setIsMfaModalOpen(false);
      setMfaCode('');
      setSimulatedMfaCode(null);
      await fetchAccountDetails();
    } catch (err: any) {
      setIsTogglingMfa(false);
      setMfaError(err.message || 'Invalid verification code.');
    }
  };

  // Simulate Self Attack (Demo tools only)
  const handleSimulateSelfAttack = async () => {
    const targetUserId = accountData?.user?.id || currentUser?.id;
    if (!targetUserId) return;

    setIsSimulating(true);
    setSimulationMessage(null);

    try {
      await api.post('/api/account-security/simulate', { userId: targetUserId });
      setIsSimulating(false);
      setSimulationMessage(
        '🚨 Simulated threat telemetry injected! Threat alert dispatched to your SOC administrator. When the administrator applies containment, this page will update in real-time.'
      );
      await fetchAccountDetails();
    } catch (err: any) {
      setIsSimulating(false);
      setSimulationMessage(err.message || 'Failed to trigger attack simulation.');
    }
  };

  if (loading && !accountData) {
    return (
      <div className="p-8 max-w-5xl mx-auto flex items-center justify-center min-h-[60vh]">
        <div className="flex flex-col items-center space-y-3 text-cyan-400">
          <RefreshCw className="w-8 h-8 animate-spin" />
          <span className="font-mono text-sm text-slate-300">Synchronizing account security credentials...</span>
        </div>
      </div>
    );
  }

  const user = accountData?.user || currentUser;
  const isLocked = user?.status === 'locked';
  const isResetRequired = user?.status === 'reset_required' || user?.mustReset;
  const isPending = user?.status === 'pending';

  const { score: securityScore, tips: securityTips } = calculateSecurityScore();
  const currentStrength = calculatePasswordStrength(newPassword);

  const getScoreBand = (score: number) => {
    if (score >= 80) return { label: 'OPTIMAL POSTURE', color: 'text-emerald-400', border: 'border-emerald-500/40', bg: 'bg-emerald-950/40' };
    if (score >= 65) return { label: 'GOOD POSTURE', color: 'text-cyan-400', border: 'border-cyan-500/40', bg: 'bg-cyan-950/40' };
    if (score >= 45) return { label: 'ATTENTION NEEDED', color: 'text-amber-400', border: 'border-amber-500/40', bg: 'bg-amber-950/40' };
    return { label: 'AT RISK', color: 'text-rose-400', border: 'border-rose-500/40', bg: 'bg-rose-950/40' };
  };

  const scoreBand = getScoreBand(securityScore);

  return (
    <div className="p-4 sm:p-6 lg:p-8 max-w-5xl mx-auto space-y-6">
      {/* CARD 1: HEADER & IDENTITY OVERVIEW */}
      <div className="bg-[#0F1420] border border-slate-800 rounded-2xl p-5 sm:p-6 shadow-xl relative overflow-hidden">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start sm:items-center space-x-4">
            <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-600 p-0.5 shadow-lg shadow-cyan-500/20 shrink-0">
              <div className="w-full h-full bg-[#0B0F17] rounded-[14px] flex items-center justify-center font-bold text-lg text-cyan-400 uppercase">
                {user?.name ? user.name.slice(0, 2) : 'US'}
              </div>
            </div>

            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white">{user?.name}</h1>
                {/* Status Chip */}
                {isLocked ? (
                  <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-950/90 text-rose-300 border border-rose-500/70">
                    <Lock className="w-3 h-3 text-rose-400" />
                    <span>LOCKED</span>
                  </span>
                ) : isResetRequired ? (
                  <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-950/90 text-amber-300 border border-amber-500/70">
                    <KeyRound className="w-3 h-3 text-amber-400" />
                    <span>RESET REQUIRED</span>
                  </span>
                ) : isPending ? (
                  <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-950/90 text-amber-300 border border-amber-500/70">
                    <Clock className="w-3 h-3 text-amber-400" />
                    <span>PENDING APPROVAL</span>
                  </span>
                ) : (
                  <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-950/60 text-emerald-300 border border-emerald-500/40">
                    <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                    <span>ACTIVE</span>
                  </span>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-400 font-mono mt-1">
                <span>{user?.email}</span>
                <span>•</span>
                <span className="text-cyan-400 flex items-center space-x-1">
                  <Building2 className="w-3 h-3" />
                  <span>{accountData?.user?.orgName || 'Institutional Organization'}</span>
                </span>
                <span>•</span>
                <span>{accountData?.activeSessionsCount === 1 ? '1 active session' : `${accountData?.activeSessionsCount || 1} active sessions`}</span>
              </div>
            </div>
          </div>

          {/* Single Sign Out Button */}
          <div className="flex items-center space-x-2 shrink-0">
            <button
              onClick={() => logout()}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 hover:text-white rounded-xl text-xs font-semibold transition flex items-center space-x-2 shadow"
            >
              <LogOut className="w-4 h-4 text-slate-400" />
              <span>Sign Out</span>
            </button>
          </div>
        </div>
      </div>

      {/* Critical Status Alerts */}
      {isLocked && (
        <div className="bg-rose-950/40 border border-rose-500/70 rounded-2xl p-5 shadow-2xl text-rose-200 flex items-start space-x-3.5">
          <ShieldAlert className="w-6 h-6 text-rose-400 shrink-0 mt-0.5 animate-pulse" />
          <div className="space-y-1">
            <h3 className="text-sm font-bold tracking-tight text-white uppercase">Your Account is Currently Locked</h3>
            <p className="text-xs text-rose-200/90 leading-relaxed">
              An institutional SOC administrator locked your account for security containment following anomalous activity. Please contact your security team to unlock access.
            </p>
          </div>
        </div>
      )}

      {isResetRequired && (
        <div className="bg-amber-950/40 border border-amber-500/70 rounded-2xl p-5 shadow-2xl text-amber-200 flex items-start space-x-3.5">
          <AlertTriangle className="w-6 h-6 text-amber-400 shrink-0 mt-0.5 animate-pulse" />
          <div className="space-y-1">
            <h3 className="text-sm font-bold tracking-tight text-white uppercase">Mandatory Password Reset Required</h3>
            <p className="text-xs text-amber-200/90 leading-relaxed">
              Your organization security policy requires you to change your password immediately. Please set a new password in Card 6 below to clear this flag.
            </p>
          </div>
        </div>
      )}

      {/* Global Success / Alert Feedback */}
      {reportSuccessMessage && (
        <div className="p-3.5 rounded-xl bg-cyan-950/40 border border-cyan-500/50 text-cyan-200 text-xs flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
            <span>{reportSuccessMessage}</span>
          </div>
          <button onClick={() => setReportSuccessMessage(null)} className="text-cyan-400 hover:text-cyan-200">
            <XCircle className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* CARD 2: MY SECURITY SCORE (0-100) */}
      <div className="bg-[#0F1420] border border-slate-800 rounded-2xl p-5 sm:p-6 shadow-xl space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-4">
          <div>
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-200 flex items-center space-x-2">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
              <span>My Security Score</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">Quantified credential hygiene and identity exposure based on your account signals</p>
          </div>
          <span className={`text-[10px] font-mono font-bold px-2.5 py-1 rounded-full border ${scoreBand.border} ${scoreBand.bg} ${scoreBand.color}`}>
            {scoreBand.label}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
          {/* Big Score Gauge */}
          <div className="flex flex-col items-center justify-center p-4 bg-[#0B0F17] border border-slate-800 rounded-xl text-center">
            <div className={`text-4xl sm:text-5xl font-black font-mono tracking-tight ${scoreBand.color}`}>
              {securityScore}
              <span className="text-lg text-slate-500 font-normal">/100</span>
            </div>
            <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden mt-3 max-w-[160px]">
              <div
                className={`h-full transition-all duration-500 ${
                  securityScore >= 80 ? 'bg-emerald-500' : securityScore >= 65 ? 'bg-cyan-500' : securityScore >= 45 ? 'bg-amber-500' : 'bg-rose-500'
                }`}
                style={{ width: `${securityScore}%` }}
              />
            </div>
            <span className="text-[11px] text-slate-400 font-mono mt-2">Account Hygiene Metric</span>
          </div>

          {/* Actionable Tips */}
          <div className="md:col-span-2 space-y-2.5">
            <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Security Recommendations</div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {securityTips.map((tip) => (
                <div
                  key={tip.id}
                  className={`p-2.5 rounded-xl border text-xs flex items-start space-x-2 transition ${
                    tip.passed
                      ? 'bg-slate-900/60 border-slate-800 text-slate-300'
                      : 'bg-amber-950/20 border-amber-700/50 text-amber-200'
                  }`}
                >
                  {tip.passed ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  )}
                  <div className="space-y-0.5">
                    <div className="font-semibold text-slate-200">{tip.title}</div>
                    <div className="text-[11px] text-slate-400 leading-snug">{tip.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* CARD 3: NOTICES FROM ADMIN */}
      <div className="bg-[#0F1420] border border-slate-800 rounded-2xl p-5 sm:p-6 shadow-xl space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
          <div className="flex items-center space-x-2">
            <Bell className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-200">Notices from Admin</h2>
          </div>
          <span className="text-[11px] text-slate-400 font-mono">
            {accountData?.notices?.length || 0} active notice(s)
          </span>
        </div>

        {(!accountData?.notices || accountData.notices.length === 0) ? (
          <div className="p-6 bg-[#0B0F17] border border-slate-800 rounded-xl text-center space-y-1">
            <CheckCircle2 className="w-6 h-6 text-emerald-400/80 mx-auto" />
            <div className="text-xs font-semibold text-slate-300">No active notices</div>
            <p className="text-[11px] text-slate-500">Your account is operating normally with no active administrative actions.</p>
          </div>
        ) : (
          <div className="space-y-2">
            {accountData.notices.map((notice) => (
              <div
                key={notice.id}
                className="p-3.5 bg-[#0B0F17] border border-cyan-800/40 rounded-xl flex items-start justify-between gap-3 shadow"
              >
                <div className="flex items-start space-x-2.5">
                  <Bell className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                  <div className="space-y-0.5">
                    <div className="text-xs font-semibold text-slate-200 flex items-center space-x-2">
                      <span>{notice.notice_type}</span>
                      <span className="text-[10px] text-slate-500 font-mono">{formatDate(notice.created_at)}</span>
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed">{notice.message}</p>
                  </div>
                </div>

                <button
                  onClick={() => handleDismissNotice(notice.id)}
                  className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white rounded-lg text-[11px] font-medium transition shrink-0"
                >
                  Dismiss
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* CARD 4: MY REPORTS ("Report Suspicious Activity") */}
      <div className="bg-[#0F1420] border border-slate-800 rounded-2xl p-5 sm:p-6 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
          <div>
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-200 flex items-center space-x-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              <span>My Security Reports</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">Report unrecognized logins or suspicious credential behavior directly to your SOC</p>
          </div>

          <button
            onClick={() => setIsReportModalOpen(true)}
            className="px-3.5 py-2 bg-gradient-to-r from-rose-600 to-rose-700 hover:from-rose-500 hover:to-rose-600 text-white rounded-xl text-xs font-semibold shadow-md shadow-rose-950/50 transition flex items-center space-x-1.5 self-start sm:self-auto"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Report Suspicious Activity</span>
          </button>
        </div>

        {/* List of Reports */}
        {(!accountData?.reports || accountData.reports.length === 0) ? (
          <div className="p-6 bg-[#0B0F17] border border-slate-800 rounded-xl text-center space-y-1">
            <CheckCircle2 className="w-6 h-6 text-slate-500 mx-auto" />
            <div className="text-xs font-semibold text-slate-300">No reports filed</div>
            <p className="text-[11px] text-slate-500">If you observe unfamiliar sign-ins or password prompt anomalies, report them above.</p>
          </div>
        ) : (
          <div className="space-y-2">
            {accountData.reports.map((report) => {
              const isResolved = report.status === 'Resolved' || report.status === 'Remediated';
              const isInvestigating = report.status === 'Investigating';
              return (
                <div
                  key={report.id}
                  className="p-3.5 bg-[#0B0F17] border border-slate-800 rounded-xl flex items-start justify-between gap-3"
                >
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span className="text-xs font-bold text-slate-200">{report.title}</span>
                      <span className={`text-[10px] font-mono font-bold px-2 py-0.2 rounded ${
                        isResolved
                          ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800'
                          : isInvestigating
                          ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-800'
                          : 'bg-amber-950/80 text-amber-300 border border-amber-800'
                      }`}>
                        {report.status}
                      </span>
                    </div>
                    <p className="text-xs text-slate-300">{report.summary}</p>
                    <div className="text-[10px] text-slate-500 font-mono">Submitted: {formatDate(report.timestamp)}</div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* CARD 5: SIGN-IN HISTORY, ACTIVE SESSIONS & MFA */}
      <div className="bg-[#0F1420] border border-slate-800 rounded-2xl p-5 sm:p-6 shadow-xl space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
          <div>
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-200 flex items-center space-x-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              <span>Sign-In History & Active Sessions</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">Review access history and remotely terminate unrecognized sessions</p>
          </div>
        </div>

        {/* Sub-Card 1: Active Sessions & MFA Quick Controls */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {/* Active Sessions */}
          <div className="p-4 bg-[#0B0F17] border border-slate-800 rounded-xl flex items-center justify-between">
            <div className="space-y-0.5">
              <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-1.5">
                <Laptop className="w-3.5 h-3.5 text-cyan-400" />
                <span>Active Sessions</span>
              </div>
              <div className="text-base font-bold text-white font-mono">
                {accountData?.activeSessionsCount === 1 ? '1 active session' : `${accountData?.activeSessionsCount || 1} active sessions`}
              </div>
              <div className="text-[10px] text-slate-500">Current authentication tokens</div>
            </div>

            <button
              onClick={handleSignOutOtherDevices}
              disabled={isRevokingSessions || (accountData?.activeSessionsCount || 1) <= 1}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 rounded-lg text-xs font-medium transition"
            >
              {isRevokingSessions ? 'Revoking...' : 'Sign out other devices'}
            </button>
          </div>

          {/* MFA Toggle */}
          <div className="p-4 bg-[#0B0F17] border border-slate-800 rounded-xl flex items-center justify-between">
            <div className="space-y-0.5">
              <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-1.5">
                <Smartphone className="w-3.5 h-3.5 text-cyan-400" />
                <span>Multi-Factor Auth (MFA)</span>
              </div>
              <div className="text-base font-bold font-mono">
                {user?.mfaRequired ? (
                  <span className="text-emerald-400">Enabled</span>
                ) : (
                  <span className="text-slate-400">Not enabled</span>
                )}
              </div>
              <div className="text-[10px] text-slate-500">Two-step verification policy</div>
            </div>

            <button
              onClick={handleOpenMfaModal}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                user?.mfaRequired
                  ? 'bg-rose-950/60 hover:bg-rose-900 border border-rose-800 text-rose-300'
                  : 'bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-700 text-cyan-300'
              }`}
            >
              {user?.mfaRequired ? 'Disable MFA' : 'Enable MFA'}
            </button>
          </div>
        </div>

        {sessionSuccessMsg && (
          <div className="p-3 bg-emerald-950/40 border border-emerald-500/40 text-emerald-300 text-xs rounded-xl flex items-center space-x-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{sessionSuccessMsg}</span>
          </div>
        )}

        {/* Sub-Card 2: Recent Sign-Ins Table */}
        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#0B0F17] text-slate-400 border-b border-slate-800 font-medium">
              <tr>
                <th className="py-3 px-4">Date & Time</th>
                <th className="py-3 px-4">Network & Location</th>
                <th className="py-3 px-4">Device / Client</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {(!accountData?.recentSignIns || accountData.recentSignIns.length === 0) ? (
                <tr>
                  <td colSpan={5} className="py-6 text-center text-slate-500 text-xs">
                    No sign-in history logged yet.
                  </td>
                </tr>
              ) : (
                accountData.recentSignIns.map((attempt) => {
                  const isSuccess = attempt.success === 1;
                  const isReported = reportedAttemptIds.has(attempt.id);
                  const isReporting = reportingAttemptId === attempt.id;

                  return (
                    <tr key={attempt.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4 font-mono text-slate-300 whitespace-nowrap">
                        {formatDate(attempt.timestamp)}
                      </td>
                      <td className="py-3 px-4">
                        <div className="text-slate-200">{formatLocation(attempt.ip_address, attempt.location)}</div>
                        <div className="text-[10px] text-slate-500 font-mono">{attempt.ip_address}</div>
                      </td>
                      <td className="py-3 px-4 max-w-xs truncate text-slate-400" title={attempt.device_fingerprint}>
                        {attempt.device_fingerprint || 'Browser Client'}
                      </td>
                      <td className="py-3 px-4">
                        {isSuccess ? (
                          <span className="inline-flex items-center space-x-1 px-2 py-0.2 rounded text-[10px] font-bold bg-emerald-950/80 text-emerald-300 border border-emerald-800">
                            SUCCESS
                          </span>
                        ) : (
                          <span className="inline-flex items-center space-x-1 px-2 py-0.2 rounded text-[10px] font-bold bg-rose-950/80 text-rose-300 border border-rose-800">
                            FAILED
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => handleThisWasntMe(attempt)}
                          disabled={isReported || isReporting}
                          className={`px-2.5 py-1 rounded text-[11px] font-medium transition ${
                            isReported
                              ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                              : 'bg-rose-950/70 hover:bg-rose-900 border border-rose-800 text-rose-300'
                          }`}
                        >
                          {isReporting ? 'Reporting...' : isReported ? 'Reported' : "This wasn't me"}
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* CARD 6: CHANGE PASSWORD */}
      <div className="bg-[#0F1420] border border-slate-800 rounded-2xl p-5 sm:p-6 shadow-xl space-y-4">
        <div className="border-b border-slate-800/80 pb-3">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-200 flex items-center space-x-2">
            <Lock className="w-4 h-4 text-cyan-400" />
            <span>Change Password</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">Update your password to restore security status or clear mandatory reset requirements</p>
        </div>

        {/* Feedback Banners (Shown strictly on active submission) */}
        {passwordSuccess && (
          <div className="p-3 bg-emerald-950/40 border border-emerald-500/50 text-emerald-300 text-xs rounded-xl flex items-center space-x-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{passwordSuccess}</span>
          </div>
        )}

        {passwordError && (
          <div className="p-3 bg-rose-950/40 border border-rose-500/50 text-rose-300 text-xs rounded-xl flex items-center space-x-2">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{passwordError}</span>
          </div>
        )}

        <form onSubmit={handlePasswordReset} className="space-y-4 max-w-lg">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">New Password</label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="Min 8 characters (letters + numbers)"
                required
                className="w-full bg-[#0B0F17] border border-slate-700/80 rounded-lg pl-3 pr-10 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>

            {newPassword && (
              <div className="mt-2 space-y-1">
                <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-300 ${currentStrength.color}`}
                    style={{ width: `${currentStrength.score}%` }}
                  />
                </div>
                <div className="flex justify-between text-[10px] text-slate-400 font-mono">
                  <span>Strength: {currentStrength.label}</span>
                  <span>{currentStrength.score}%</span>
                </div>
              </div>
            )}
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Confirm New Password</label>
            <input
              type={showPassword ? 'text' : 'password'}
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Re-enter new password"
              required
              className="w-full bg-[#0B0F17] border border-slate-700/80 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <button
            type="submit"
            disabled={isSubmittingPassword}
            className="py-2.5 px-5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-semibold text-xs rounded-lg shadow-md transition flex items-center space-x-2"
          >
            <span>{isSubmittingPassword ? 'Updating Password...' : 'Save New Password'}</span>
            <Check className="w-3.5 h-3.5" />
          </button>
        </form>
      </div>

      {/* DEMO TOOLS ACCORDION (COLLAPSIBLE, SHOWN ONLY WHEN DEMO_MODE IS ACTIVE) */}
      {isDemoMode && (
        <div className="border border-slate-800/80 rounded-2xl overflow-hidden bg-[#0F1420]/60">
          <button
            type="button"
            onClick={() => setIsDemoToolsOpen(!isDemoToolsOpen)}
            className="w-full p-4 flex items-center justify-between text-xs font-semibold text-slate-400 hover:text-slate-200 transition"
          >
            <div className="flex items-center space-x-2">
              <Play className="w-3.5 h-3.5 text-cyan-400" />
              <span>Demo Tools (Prototype Evaluation Only)</span>
            </div>
            {isDemoToolsOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>

          {isDemoToolsOpen && (
            <div className="p-4 border-t border-slate-800/80 space-y-3 bg-[#0B0F17]/80 text-xs">
              <p className="text-slate-300 leading-relaxed">
                Test the end-to-end security response story: trigger a simulated attack against your own credentials. The intrusion will be detected immediately by the detection engine, elevating the organization risk score and dispatching a high-priority alert to the SOC Console.
              </p>

              {simulationMessage && (
                <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-600/40 text-rose-200 text-xs">
                  {simulationMessage}
                </div>
              )}

              <button
                onClick={handleSimulateSelfAttack}
                disabled={isSimulating}
                className="px-4 py-2 bg-rose-950 hover:bg-rose-900 border border-rose-600/60 text-rose-300 rounded-xl text-xs font-semibold transition flex items-center space-x-2"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>{isSimulating ? 'Injecting Attack...' : 'Simulate Attack on My Account'}</span>
              </button>
            </div>
          )}
        </div>
      )}

      {/* MODAL: REPORT SUSPICIOUS ACTIVITY */}
      {isReportModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="w-full max-w-lg bg-[#0F1420] border border-slate-800 rounded-2xl p-6 shadow-2xl relative space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2 text-rose-400">
                <ShieldAlert className="w-5 h-5" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">Report Suspicious Activity</h3>
              </div>
              <button
                onClick={() => setIsReportModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 text-xs"
              >
                Cancel
              </button>
            </div>

            <form onSubmit={handleReportSuspicious} className="space-y-4">
              <p className="text-xs text-slate-300 leading-relaxed">
                Provide details about the suspicious activity (e.g. unrecognized sign-ins, strange MFA push prompts, or unauthorized data access). This immediately generates an urgent alert for your organization's SOC administrator.
              </p>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Incident Details</label>
                <textarea
                  rows={4}
                  value={reportDetails}
                  onChange={(e) => setReportDetails(e.target.value)}
                  placeholder="Describe what occurred (e.g. Received an MFA push prompt while asleep from an unknown IP)..."
                  required
                  className="w-full bg-[#0B0F17] border border-slate-700 rounded-lg p-3 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-rose-500 leading-relaxed"
                />
              </div>

              <div className="flex items-center justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsReportModalOpen(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-medium transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmittingReport || !reportDetails.trim()}
                  className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-xl text-xs font-semibold shadow-md transition flex items-center space-x-1.5"
                >
                  <span>{isSubmittingReport ? 'Filing Alert...' : 'Submit Incident Report'}</span>
                  <Send className="w-3.5 h-3.5" />
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL: MFA TOGGLE WITH SIMULATED CODE */}
      {isMfaModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="w-full max-w-md bg-[#0F1420] border border-slate-800 rounded-2xl p-6 shadow-2xl relative space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2 text-cyan-400">
                <Smartphone className="w-5 h-5" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  {user?.mfaRequired ? 'Disable Multi-Factor Auth' : 'Setup Multi-Factor Auth'}
                </h3>
              </div>
              <button
                onClick={() => setIsMfaModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 text-xs"
              >
                Cancel
              </button>
            </div>

            {mfaError && (
              <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs">
                {mfaError}
              </div>
            )}

            {!user?.mfaRequired ? (
              <div className="space-y-4">
                <p className="text-xs text-slate-300 leading-relaxed">
                  Enter the 6-digit verification code dispatched to <span className="text-cyan-400 font-mono">{user?.email}</span> to confirm your identity and enable MFA.
                </p>

                {simulatedMfaCode && (
                  <div className="p-3 bg-cyan-950/60 border border-cyan-800 rounded-xl flex items-center justify-between">
                    <div>
                      <div className="text-[10px] uppercase font-mono text-cyan-400 font-bold">Simulated SMS/Email Code</div>
                      <div className="text-base font-bold font-mono text-cyan-300 tracking-widest">{simulatedMfaCode}</div>
                    </div>
                    <button
                      type="button"
                      onClick={() => setMfaCode(simulatedMfaCode)}
                      className="text-xs bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 px-2.5 py-1 rounded"
                    >
                      Autofill Code
                    </button>
                  </div>
                )}

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">6-Digit Code</label>
                  <input
                    type="text"
                    maxLength={6}
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))}
                    placeholder="123456"
                    className="w-full bg-[#0B0F17] border border-slate-700 rounded-lg px-3.5 py-2 text-center text-lg text-cyan-300 font-mono tracking-widest focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <button
                  type="button"
                  onClick={handleConfirmMfaToggle}
                  disabled={isTogglingMfa || mfaCode.length !== 6}
                  className="w-full py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 font-semibold text-xs rounded-lg shadow-md transition disabled:opacity-50"
                >
                  {isTogglingMfa ? 'Enabling...' : 'Verify & Enable MFA'}
                </button>
              </div>
            ) : (
              <div className="space-y-4">
                <p className="text-xs text-slate-300 leading-relaxed">
                  Are you sure you want to disable Multi-Factor Authentication? Disabling MFA significantly lowers your security score and makes your account vulnerable to credential compromise.
                </p>

                <div className="flex items-center justify-end space-x-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setIsMfaModalOpen(false)}
                    className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-medium transition"
                  >
                    Keep MFA Enabled
                  </button>
                  <button
                    type="button"
                    onClick={handleConfirmMfaToggle}
                    disabled={isTogglingMfa}
                    className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-xl text-xs font-semibold shadow-md transition"
                  >
                    {isTogglingMfa ? 'Disabling...' : 'Confirm Disable MFA'}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
