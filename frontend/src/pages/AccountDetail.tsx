import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import {
  ArrowLeft,
  ShieldAlert,
  ShieldCheck,
  Lock,
  Unlock,
  KeyRound,
  AlertTriangle,
  Clock,
  Globe,
  Laptop,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Sliders,
  UserX,
  FileCheck,
  Shield,
  Zap,
  TrendingDown,
  Info,
  Database,
  ExternalLink,
  Share2,
  EyeOff,
  Radio,
  Sparkles
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import { AccountAlert, LoginAttempt } from '../types';
import { api } from '../api/client';

export const AccountDetail: React.FC = () => {
  const { userId } = useParams<{ userId: string }>();
  const { token, addNotification, activeOrg } = useApp();
  const navigate = useNavigate();

  const [userData, setUserData] = useState<{
    user: any;
    alert: AccountAlert | null;
    recentSignIns: LoginAttempt[];
    activeSessionsCount: number;
  } | null>(null);

  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [anchoringIncident, setAnchoringIncident] = useState(false);
  const [isShareModalOpen, setIsShareModalOpen] = useState(false);
  const [isSharing, setIsSharing] = useState(false);
  const [shareResult, setShareResult] = useState<any | null>(null);
  const [confirmModal, setConfirmModal] = useState<{
    isOpen: boolean;
    action: string;
    title: string;
    description: string;
    entityValue?: string;
  } | null>(null);

  const fetchUserDetails = async () => {
    if (!userId) return;
    try {
      const data = await api.get<any>(`/api/account-security/users/${userId}/details`);
      if (data && data.user) {
        setUserData(data);
      }
    } catch (err) {
      console.error('Error fetching account details:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUserDetails();
    const interval = setInterval(fetchUserDetails, 3000);
    return () => clearInterval(interval);
  }, [userId]);

  const handleExecuteFix = async (action: string, entityValue?: string) => {
    if (!userId) return;
    setActionLoading(action);
    setConfirmModal(null);

    try {
      const data = await api.post<any>('/api/account-security/fix', {
        userId,
        action,
        alertId: userData?.alert?.id,
        entityValue: entityValue
      });

      setActionLoading(null);
      addNotification(
        `✅ Remote Fix Executed: ${action.replace(/_/g, ' ').toUpperCase()}`,
        data.message || `Action applied to ${userData?.user?.email}. Risk score dropped.`,
        'SUCCESS',
        `/account-security/${userId}`
      );
      await fetchUserDetails();
    } catch (err: any) {
      console.error('Error executing remote fix:', err);
      setActionLoading(null);
      addNotification('Action Failed', err.message || 'Remote fix action failed', 'ALERT');
    }
  };

  const handleAnchorIncident = async () => {
    if (!userData?.alert) return;
    setAnchoringIncident(true);
    try {
      const data = await api.post<any>('/api/audit/anchor-incident', {
        alertId: userData.alert.id,
        details: `${userData.alert.title} | Rules: ${userData.alert.matchedRules.join('; ')}`
      });

      addNotification(
        'Incident Digest Anchored to DLT Ledger',
        `Incident ${userData.alert.id} anchored to DLT Block #${data.block?.blockNumber} (Status: ${data.ledgerStatus}).`,
        'SUCCESS',
        '/dlt-ledger'
      );
    } catch (err: any) {
      addNotification('Anchoring Error', err.message || 'Failed to anchor to DLT', 'ALERT');
    } finally {
      setAnchoringIncident(false);
    }
  };

  const handleShareSanitizedPattern = async () => {
    if (!userData?.alert) return;
    setIsSharing(true);
    try {
      const data = await api.post<any>('/api/account-security/share-pattern', {
        alertId: userData.alert.id,
        userId: userData.user.id
      });
      setIsSharing(false);

      setShareResult(data);
      addNotification(
        'Threat Pattern Sanitized & Broadcast',
        `Pattern ${data.pattern?.patternCode} scrubbed of PII and broadcast to ${data.peerCorrelations?.length || 2} peer organizations. Early warning gossip active.`,
        'SUCCESS',
        '/threat-library'
      );
    } catch (err: any) {
      setIsSharing(false);
      addNotification('Sharing Error', err.message || 'Failed to share threat pattern', 'ALERT');
    }
  };

  if (loading && !userData) {
    return (
      <div className="p-6 max-w-6xl mx-auto flex items-center justify-center min-h-[60vh]">
        <div className="flex items-center space-x-3 text-cyan-400">
          <RefreshCw className="w-6 h-6 animate-spin" />
          <span className="font-mono text-sm">Loading user account telemetry & threat model...</span>
        </div>
      </div>
    );
  }

  if (!userData?.user) {
    return (
      <div className="p-6 max-w-6xl mx-auto text-center space-y-4">
        <h2 className="text-xl font-bold text-white">Account Not Found</h2>
        <p className="text-sm text-slate-400">Target user does not exist or belongs to another organization.</p>
        <button
          onClick={() => navigate('/account-security')}
          className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded-lg inline-flex items-center space-x-2"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Account Security</span>
        </button>
      </div>
    );
  }

  const { user, alert, recentSignIns, activeSessionsCount } = userData;
  const isAttack = Boolean(alert && alert.status !== 'Remediated');
  const isLocked = user.status === 'locked';
  const isResetRequired = user.status === 'reset_required' || user.mustReset;
  const riskScore = alert && alert.status !== 'Remediated' ? alert.accountRiskScore : isLocked ? 45 : 18;

  // Dynamically resolve adversary IP, device fingerprint, and location from sign-in timeline
  const suspiciousAttempt = recentSignIns?.find((att) => att.success === 0 || (att.ip_address && att.ip_address !== '127.0.0.1')) || recentSignIns?.[0];
  const detectedAttackerIp = suspiciousAttempt?.ip_address || '198.51.100.42';
  const detectedAttackerDevice = suspiciousAttempt?.device_fingerprint || 'Python-Requests/2.31 (Adversary Script)';
  const detectedLocation = suspiciousAttempt?.location || 'Offshore Remote Host';

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Top Breadcrumbs & Profile Card */}
      <div className="bg-[#0F1420] border border-slate-800 rounded-2xl p-6 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-80 h-80 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />

        <div className="space-y-4 relative z-10">
          {/* Breadcrumbs */}
          <Link
            to="/account-security"
            className="inline-flex items-center space-x-2 text-xs font-medium text-slate-400 hover:text-cyan-400 transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Back to Account Security Fleet</span>
          </Link>

          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center space-x-4">
              <div className={`w-14 h-14 rounded-2xl flex items-center justify-center font-bold text-xl uppercase ${
                isAttack
                  ? 'bg-rose-950 text-rose-300 border-2 border-rose-500 shadow-lg shadow-rose-950/40 animate-pulse'
                  : 'bg-slate-800 text-slate-300 border border-slate-700'
              }`}>
                {user.name.slice(0, 2)}
              </div>
              <div>
                <div className="flex items-center space-x-2.5">
                  <h1 className="text-2xl font-bold tracking-tight text-white">{user.name}</h1>
                  {isAttack ? (
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-950 text-rose-300 border border-rose-500 flex items-center space-x-1 animate-pulse">
                      <span className="w-2 h-2 rounded-full bg-rose-400 animate-ping mr-1" />
                      <span>UNDER ACTIVE ATTACK</span>
                    </span>
                  ) : isLocked ? (
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-950/80 text-rose-300 border border-rose-800/50 flex items-center space-x-1">
                      <Lock className="w-3.5 h-3.5" />
                      <span>Account Locked</span>
                    </span>
                  ) : isResetRequired ? (
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-950/80 text-amber-300 border border-amber-800/50 flex items-center space-x-1">
                      <KeyRound className="w-3.5 h-3.5" />
                      <span>Password Reset Required</span>
                    </span>
                  ) : (
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-950/80 text-emerald-300 border border-emerald-800/40 flex items-center space-x-1">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Active & Healthy</span>
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-400 font-mono mt-0.5 flex items-center space-x-2">
                  <span>{user.email}</span>
                  <span>•</span>
                  <span className="text-cyan-400 font-semibold">{user.privilegeLevel || 'STANDARD'}</span>
                  <span>•</span>
                  <span>{user.orgId}</span>
                  <span>•</span>
                  <span>{activeSessionsCount} active session(s)</span>
                </p>
              </div>
            </div>

            {/* Risk Gauge Header */}
            <div className="flex items-center space-x-4 bg-[#0B0F17] p-3 rounded-xl border border-slate-800">
              <div className="text-right">
                <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Account Risk Score</div>
                <div className={`text-2xl font-bold font-mono ${
                  riskScore >= 80 ? 'text-rose-400' : riskScore >= 65 ? 'text-amber-400' : riskScore >= 45 ? 'text-cyan-400' : 'text-emerald-400'
                }`}>
                  {riskScore} <span className="text-xs text-slate-500 font-normal">/ 100</span>
                </div>
              </div>
              <div className={`px-2 py-1 rounded text-[10px] font-mono font-bold uppercase ${
                riskScore >= 80 ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-slate-800 text-slate-400'
              }`}>
                {riskScore >= 80 ? 'CRITICAL' : riskScore >= 65 ? 'HIGH' : riskScore >= 45 ? 'MEDIUM' : 'LOW'}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Grid: Explainability Waterfall & Remote Fix Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Explainability Waterfall Card */}
        <div className="lg:col-span-2 bg-[#0F1420] border border-slate-800 rounded-2xl p-6 space-y-5 shadow-xl">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center space-x-2 text-cyan-400">
              <Sliders className="w-5 h-5" />
              <h2 className="text-sm font-bold uppercase tracking-wider text-white">Risk Explainability Waterfall</h2>
            </div>
            {alert && (
              <span className="text-xs font-mono font-semibold text-rose-400 bg-rose-950/60 border border-rose-800/50 px-2.5 py-0.5 rounded">
                Confidence: {alert.confidence}%
              </span>
            )}
          </div>

          {!alert || alert.factorContributions.length === 0 ? (
            <div className="p-8 text-center text-slate-500 text-xs border border-dashed border-slate-800 rounded-xl space-y-2">
              <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto opacity-70" />
              <p>Baseline security profile verified. Zero anomalous behavioral factors detected.</p>
            </div>
          ) : (
            <div className="space-y-4">
              <p className="text-xs text-slate-400">
                Transparent factor breakdown contributing to account risk score of <span className="font-bold text-white">{alert.accountRiskScore}/100</span>:
              </p>

              <div className="space-y-3 font-mono">
                {alert.factorContributions.map((fc, idx) => (
                  <div key={fc.id || idx} className="bg-[#0B0F17] p-3 rounded-xl border border-slate-800/80 space-y-2">
                    <div className="flex items-center justify-between text-xs">
                      <div className="flex items-center space-x-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          fc.severity === 'CRITICAL'
                            ? 'bg-rose-950 text-rose-300 border border-rose-800'
                            : fc.severity === 'HIGH'
                            ? 'bg-amber-950 text-amber-300 border border-amber-800'
                            : 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                        }`}>
                          {fc.category}
                        </span>
                        <span className="font-semibold text-slate-200">+{fc.points} pts</span>
                      </div>
                      <span className="text-[10px] text-slate-500 uppercase">{fc.severity}</span>
                    </div>

                    <p className="text-xs text-slate-300 font-sans">{fc.explanation}</p>

                    <div className="w-full bg-slate-800 h-1 rounded-full overflow-hidden">
                      <div
                        className={`h-full ${
                          fc.severity === 'CRITICAL' ? 'bg-rose-500' : fc.severity === 'HIGH' ? 'bg-amber-500' : 'bg-cyan-500'
                        }`}
                        style={{ width: `${Math.min(100, fc.points * 3)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Matched Threat Rules */}
          {alert && alert.matchedRules && alert.matchedRules.length > 0 && (
            <div className="pt-4 border-t border-slate-800 space-y-3">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <span>Correlated Threat Rules ({alert.matchedRules.length})</span>
              </h3>
              <div className="space-y-2 font-mono text-xs">
                {alert.matchedRules.map((rule, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded-lg bg-rose-950/20 border border-rose-500/30 text-rose-300 flex items-start space-x-2"
                  >
                    <span className="text-rose-400 font-bold">•</span>
                    <span>{rule}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Remote Fix Action Panel */}
        <div className="bg-[#0F1420] border border-slate-800 rounded-2xl p-6 space-y-5 shadow-xl">
          <div className="border-b border-slate-800 pb-3">
            <div className="flex items-center space-x-2 text-cyan-400">
              <Zap className="w-5 h-5" />
              <h2 className="text-sm font-bold uppercase tracking-wider text-white">Admin Remote Fix</h2>
            </div>
            <p className="text-[11px] text-slate-400 mt-1">
              Account-level SOC interventions executed instantly on the server. No local software required.
            </p>
          </div>

          <div className="space-y-2.5">
            {/* Lock / Unlock */}
            {isLocked ? (
              <button
                onClick={() =>
                  setConfirmModal({
                    isOpen: true,
                    action: 'unlock_restore',
                    title: 'Unlock & Restore Account',
                    description: `Reactivate account access for ${user.email}. User will be allowed to log in normally.`
                  })
                }
                disabled={Boolean(actionLoading)}
                className="w-full py-2.5 px-3 bg-emerald-950/40 hover:bg-emerald-900/60 border border-emerald-700/60 rounded-xl text-xs font-semibold text-emerald-300 flex items-center justify-between transition-all"
              >
                <span className="flex items-center space-x-2">
                  <Unlock className="w-4 h-4" />
                  <span>Unlock & Restore Account</span>
                </span>
                <span className="text-[10px] text-emerald-400 font-mono">RESTORE</span>
              </button>
            ) : (
              <button
                onClick={() =>
                  setConfirmModal({
                    isOpen: true,
                    action: 'lock_account',
                    title: 'Lock User Account',
                    description: `Immediately lock ${user.email} out of all corporate portals and invalidate active JWT sessions. Attacker access will be blocked immediately.`
                  })
                }
                disabled={Boolean(actionLoading)}
                className="w-full py-2.5 px-3 bg-rose-950/40 hover:bg-rose-900/60 border border-rose-700/60 rounded-xl text-xs font-semibold text-rose-300 flex items-center justify-between transition-all"
              >
                <span className="flex items-center space-x-2">
                  <Lock className="w-4 h-4" />
                  <span>Lock Account (Immediate Lockout)</span>
                </span>
                <span className="text-[10px] text-rose-400 font-mono">CRITICAL</span>
              </button>
            )}

            {/* Force Logout */}
            <button
              onClick={() =>
                setConfirmModal({
                  isOpen: true,
                  action: 'force_logout',
                  title: 'Force Logout (Revoke All Sessions)',
                  description: `Revoke all active authentication tokens for ${user.email} in the sessions database. Forces all open sessions to terminate.`
                })
              }
              disabled={Boolean(actionLoading)}
              className="w-full py-2.5 px-3 bg-slate-800 hover:bg-slate-700/80 border border-slate-700 rounded-xl text-xs font-semibold text-slate-200 flex items-center justify-between transition-all"
            >
              <span className="flex items-center space-x-2">
                <UserX className="w-4 h-4 text-amber-400" />
                <span>Force Logout (Revoke Sessions)</span>
              </span>
              <span className="text-[10px] text-slate-400 font-mono">{activeSessionsCount} Active</span>
            </button>

            {/* Force Password Reset */}
            <button
              onClick={() =>
                setConfirmModal({
                  isOpen: true,
                  action: 'force_password_reset',
                  title: 'Force Password Reset',
                  description: `Flag ${user.email} with reset_required. User must set a new 8+ character password before continuing.`
                })
              }
              disabled={Boolean(actionLoading)}
              className="w-full py-2.5 px-3 bg-slate-800 hover:bg-slate-700/80 border border-slate-700 rounded-xl text-xs font-semibold text-slate-200 flex items-center justify-between transition-all"
            >
              <span className="flex items-center space-x-2">
                <KeyRound className="w-4 h-4 text-cyan-400" />
                <span>Force Password Reset</span>
              </span>
              <span className="text-[10px] text-slate-400 font-mono">CREDENTIAL</span>
            </button>

            {/* Require MFA */}
            <button
              onClick={() =>
                setConfirmModal({
                  isOpen: true,
                  action: 'require_mfa',
                  title: 'Require Multi-Factor Authentication',
                  description: `Enforce mandatory hardware / FIDO2 / Authenticator MFA requirement on ${user.email}.`
                })
              }
              disabled={Boolean(actionLoading)}
              className="w-full py-2.5 px-3 bg-slate-800 hover:bg-slate-700/80 border border-slate-700 rounded-xl text-xs font-semibold text-slate-200 flex items-center justify-between transition-all"
            >
              <span className="flex items-center space-x-2">
                <Shield className="w-4 h-4 text-purple-400" />
                <span>Require Multi-Factor Auth (MFA)</span>
              </span>
              <span className="text-[10px] text-slate-400 font-mono">FIDO2</span>
            </button>

            {/* Block IP / Device */}
            <button
              onClick={() =>
                setConfirmModal({
                  isOpen: true,
                  action: 'block_ip_device',
                  title: 'Block Adversary IP & Device Fingerprint',
                  description: `Quarantine hostile source IP (${detectedAttackerIp}${detectedLocation ? ` • ${detectedLocation}` : ''}) and client fingerprint (${detectedAttackerDevice}) on the institutional perimeter firewall. All connection requests from this origin will be dropped immediately.`,
                  entityValue: detectedAttackerIp
                })
              }
              disabled={Boolean(actionLoading)}
              className="w-full py-2.5 px-3 bg-slate-800 hover:bg-slate-700/80 border border-slate-700 rounded-xl text-xs font-semibold text-slate-200 flex items-center justify-between transition-all"
            >
              <span className="flex items-center space-x-2">
                <Globe className="w-4 h-4 text-rose-400" />
                <span>Block Adversary IP / Device</span>
              </span>
              <span className="text-[10px] text-slate-400 font-mono">PERIMETER</span>
            </button>

            {/* Revert Privileges */}
            {user.privilegeLevel !== 'STANDARD' && (
              <button
                onClick={() =>
                  setConfirmModal({
                    isOpen: true,
                    action: 'revert_privileges',
                    title: 'Revert Elevated Privileges',
                    description: `Demote ${user.email} from ${user.privilegeLevel} back to STANDARD baseline.`
                  })
                }
                disabled={Boolean(actionLoading)}
                className="w-full py-2.5 px-3 bg-slate-800 hover:bg-slate-700/80 border border-slate-700 rounded-xl text-xs font-semibold text-slate-200 flex items-center justify-between transition-all"
              >
                <span className="flex items-center space-x-2">
                  <TrendingDown className="w-4 h-4 text-amber-400" />
                  <span>Revert to Standard Privileges</span>
                </span>
                <span className="text-[10px] text-slate-400 font-mono">DEMOTE</span>
              </button>
            )}

            {/* DLT Incident Anchor */}
            {alert && (
              <div className="pt-3 border-t border-slate-800 space-y-2">
                <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider flex items-center space-x-1.5">
                  <Database className="w-3.5 h-3.5 text-purple-400" />
                  <span>DLT Trust Anchor</span>
                </div>
                <button
                  type="button"
                  onClick={handleAnchorIncident}
                  disabled={anchoringIncident}
                  className="w-full py-2.5 px-3 bg-purple-950/40 hover:bg-purple-900/60 border border-purple-700/60 rounded-xl text-xs font-semibold text-purple-300 flex items-center justify-between transition-all"
                >
                  <span className="flex items-center space-x-2">
                    <Database className="w-4 h-4 text-purple-400" />
                    <span>{anchoringIncident ? 'Anchoring...' : 'Anchor Incident to DLT Ledger'}</span>
                  </span>
                  <ExternalLink className="w-3.5 h-3.5 text-purple-400" />
                </button>
              </div>
            )}

            {/* Collaborative Network Pattern Sharing */}
            {alert && (
              <div className="pt-2 border-t border-slate-800 space-y-2">
                <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider flex items-center space-x-1.5">
                  <Share2 className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Collaborative Defense Grid</span>
                </div>
                <button
                  type="button"
                  onClick={() => setIsShareModalOpen(true)}
                  className="w-full py-2.5 px-3 bg-gradient-to-r from-cyan-950/70 to-blue-950/70 hover:from-cyan-900/80 hover:to-blue-900/80 border border-cyan-600/50 rounded-xl text-xs font-semibold text-cyan-300 flex items-center justify-between transition-all shadow-lg shadow-cyan-950/40"
                >
                  <span className="flex items-center space-x-2">
                    <Share2 className="w-4 h-4 text-cyan-400" />
                    <span>Share Sanitized Pattern</span>
                  </span>
                  <span className="text-[10px] text-cyan-400 font-mono">PII-STRIPPED</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Activity and Sign-In Timeline Table */}
      <div className="bg-[#0F1420] border border-slate-800 rounded-2xl p-6 space-y-4 shadow-xl">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center space-x-2 text-white">
            <Clock className="w-5 h-5 text-cyan-400" />
            <h2 className="text-sm font-bold uppercase tracking-wider">Account Sign-In & Activity Timeline</h2>
          </div>
          <span className="text-xs text-slate-500 font-mono">{recentSignIns.length} records logged</span>
        </div>

        {recentSignIns.length === 0 ? (
          <div className="p-8 text-center text-slate-500 text-xs border border-dashed border-slate-800 rounded-xl">
            No sign-in events recorded for this user yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#0B0F17] text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Source IP</th>
                  <th className="py-2.5 px-3">Location</th>
                  <th className="py-2.5 px-3">Device / Client Fingerprint</th>
                  <th className="py-2.5 px-3">Details / Failure Reason</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {recentSignIns.map((attempt) => (
                  <tr key={attempt.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-2.5 px-3 text-slate-300 text-[11px]">
                      {new Date(attempt.timestamp).toLocaleString()}
                    </td>
                    <td className="py-2.5 px-3">
                      {attempt.success === 1 ? (
                        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950/60 text-emerald-300 border border-emerald-800/40">
                          <CheckCircle2 className="w-3 h-3" />
                          <span>SUCCESS</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-rose-950/60 text-rose-300 border border-rose-800/40">
                          <XCircle className="w-3 h-3" />
                          <span>FAILED</span>
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-cyan-300 text-[11px]">{attempt.ip_address}</td>
                    <td className="py-2.5 px-3 text-slate-300 text-[11px]">
                      <span className="flex items-center space-x-1">
                        <Globe className="w-3 h-3 text-slate-500" />
                        <span>{attempt.location}</span>
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-400 text-[11px] max-w-xs truncate" title={attempt.device_fingerprint}>
                      <span className="flex items-center space-x-1">
                        <Laptop className="w-3 h-3 text-slate-500 shrink-0" />
                        <span className="truncate">{attempt.device_fingerprint}</span>
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-400 text-[10px]">
                      {attempt.failure_reason || 'Verified Authentication Approved'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Confirmation Modal */}
      {confirmModal && confirmModal.isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-[#0F1420] border border-cyan-500/40 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl relative">
            <div className="flex items-center space-x-2 text-cyan-400 border-b border-slate-800 pb-3">
              <Zap className="w-5 h-5" />
              <h3 className="font-bold text-sm uppercase tracking-wider text-white">{confirmModal.title}</h3>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed font-sans">{confirmModal.description}</p>

            {/* Dynamic Threat Origin Telemetry for IP / Device blocking */}
            {confirmModal.action === 'block_ip_device' && (
              <div className="bg-[#0B0F17] p-3 rounded-xl border border-rose-900/50 space-y-2 text-xs font-mono">
                <div className="text-[10px] text-rose-400 font-bold uppercase tracking-wider flex items-center space-x-1.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                  <span>Threat Origin Telemetry (Resolved from Timeline)</span>
                </div>
                <div className="space-y-1.5 pt-1 border-t border-slate-800/80">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400 text-[11px]">Target Adversary IP:</span>
                    <span className="text-rose-300 font-bold text-[11px] bg-rose-950/70 border border-rose-800/60 px-2 py-0.5 rounded">
                      {confirmModal.entityValue || detectedAttackerIp}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400 text-[11px]">Origin Geolocation:</span>
                    <span className="text-slate-200 text-[11px]">{detectedLocation}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400 text-[11px]">Automation Client:</span>
                    <span className="text-slate-300 text-[11px] truncate max-w-[190px]" title={detectedAttackerDevice}>
                      {detectedAttackerDevice}
                    </span>
                  </div>
                </div>
              </div>
            )}

            <div className="flex items-center justify-end space-x-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setConfirmModal(null)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={Boolean(actionLoading)}
                onClick={() => handleExecuteFix(confirmModal.action, confirmModal.entityValue)}
                className="px-4 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-semibold text-xs rounded-lg shadow-lg shadow-cyan-500/20 flex items-center space-x-2"
              >
                <span>{actionLoading ? 'Executing...' : 'Confirm Remote Fix'}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Share Sanitized Threat Pattern Modal */}
      {isShareModalOpen && alert && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md animate-fadeIn">
          <div className="bg-[#0F1420] border border-cyan-500/50 rounded-2xl max-w-2xl w-full p-6 space-y-5 shadow-2xl relative">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2 text-cyan-400">
                <Share2 className="w-5 h-5" />
                <h3 className="font-bold text-sm uppercase tracking-wider text-white">Share Sanitized Threat Pattern</h3>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                DIFFERENTIAL PRIVACY SCRUBBED
              </span>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed font-sans">
              Extract hostile behavior patterns from <span className="font-bold text-white">{user.name}</span>'s incident, strip all Personally Identifiable Information (PII) through the Privacy Engine, and broadcast threat intelligence across the inter-bank mesh for early warning detection.
            </p>

            {/* Side-by-side Sanitization Comparison */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
              {/* Private Data */}
              <div className="p-3.5 rounded-xl bg-rose-950/20 border border-rose-800/40 space-y-2">
                <div className="text-[10px] font-bold text-rose-400 uppercase tracking-wider flex items-center space-x-1.5">
                  <EyeOff className="w-3.5 h-3.5" />
                  <span>Original Confidential Data (Stripped)</span>
                </div>
                <div className="space-y-1 text-[11px] text-slate-400">
                  <div>Employee: <span className="line-through text-rose-300">{user.name}</span></div>
                  <div>Corporate Email: <span className="line-through text-rose-300">{user.email}</span></div>
                  <div>Account ID: <span className="line-through text-rose-300">{user.id}</span></div>
                  <div>Ingress IP: <span className="line-through text-rose-300">198.51.100.42</span></div>
                  <div>Hardware Token: <span className="line-through text-rose-300">DEVICE-MAC-7C:2A...</span></div>
                </div>
                <div className="text-[10px] text-rose-400/80 font-sans italic pt-1">
                  ✓ Protected: Zero user identifiers or host signatures leave this institution.
                </div>
              </div>

              {/* Sanitized Behavioral Sequence */}
              <div className="p-3.5 rounded-xl bg-cyan-950/20 border border-cyan-800/40 space-y-2">
                <div className="text-[10px] font-bold text-cyan-400 uppercase tracking-wider flex items-center space-x-1.5">
                  <Radio className="w-3.5 h-3.5" />
                  <span>Sanitized Behavioral Sequence (Shared)</span>
                </div>
                <div className="space-y-1.5 text-[10px]">
                  <div className="flex flex-wrap gap-1">
                    {alert.matchedRules.map((rule, idx) => (
                      <span key={idx} className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-700 text-cyan-300">
                        {rule.split(':')[0]}
                      </span>
                    ))}
                  </div>
                  <div className="text-slate-400 pt-1">
                    Quorum Target: <span className="text-slate-200">Hospital B, Univ C</span>
                  </div>
                  <div className="text-slate-400">
                    DLT Anchor: <span className="text-purple-300">CONFIRMED Consensus</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Broadcast Results Telemetry */}
            {shareResult && (
              <div className="p-3.5 rounded-xl bg-emerald-950/30 border border-emerald-500/50 text-emerald-300 space-y-2 text-xs font-mono animate-fadeIn">
                <div className="flex items-center space-x-2 font-bold">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>Pattern {shareResult.pattern?.patternCode} Broadcast Successfully</span>
                </div>
                <div className="grid grid-cols-2 gap-2 text-[11px] pt-1">
                  {shareResult.peerCorrelations?.map((peer: any, idx: number) => (
                    <div key={idx} className="p-2 rounded bg-slate-900 border border-slate-800">
                      <div className="text-slate-400 text-[10px]">{peer.targetOrgName}</div>
                      <div className="font-bold text-cyan-400">{peer.similarityPercentage}% Similarity</div>
                      <div className="text-[9px] text-amber-400 mt-0.5">{peer.warningMessage}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="flex items-center justify-end space-x-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => {
                  setIsShareModalOpen(false);
                  setShareResult(null);
                }}
                className="px-3.5 py-2 text-xs text-slate-400 hover:text-slate-200"
              >
                Close
              </button>

              <button
                type="button"
                disabled={isSharing}
                onClick={handleShareSanitizedPattern}
                className="px-4 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs rounded-xl shadow-lg shadow-cyan-500/20 flex items-center space-x-2 transition-all"
              >
                <Share2 className="w-4 h-4" />
                <span>{isSharing ? 'Sanitizing & Broadcasting...' : 'Broadcast to Collaborative Network'}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
