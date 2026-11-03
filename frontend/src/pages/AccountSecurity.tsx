import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  ShieldCheck,
  Lock,
  KeyRound,
  AlertTriangle,
  UserCheck,
  Search,
  Filter,
  ArrowUpDown,
  RefreshCw,
  Play,
  Users,
  Building2,
  ExternalLink,
  CheckCircle2,
  XCircle,
  Eye,
  Shield,
  Sparkles,
  RotateCcw,
  Share2,
  Radio,
  Check,
  Clock
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import { AuthUser, AccountAlert } from '../types';
import { api } from '../api/client';

export const AccountSecurity: React.FC = () => {
  const { token, activeOrg, addNotification } = useApp();
  const navigate = useNavigate();

  const [users, setUsers] = useState<any[]>([]);
  const [alerts, setAlerts] = useState<AccountAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'ACTIVE' | 'ATTACK' | 'LOCKED' | 'RESET'>('ALL');
  const [privilegeFilter, setPrivilegeFilter] = useState<string>('ALL');
  const [sortOrder, setSortOrder] = useState<'DESC' | 'ASC'>('DESC');
  const [joinCode, setJoinCode] = useState<string>('');
  const [copiedCode, setCopiedCode] = useState<boolean>(false);

  // Simulation Modal State
  const [isSimModalOpen, setIsSimModalOpen] = useState(false);
  const [selectedSimUser, setSelectedSimUser] = useState<string>('');
  const [selectedAttackType, setSelectedAttackType] = useState<string>('ALL');
  const [isSimulating, setIsSimulating] = useState(false);

  // Phase 6: Account Attack Demo State
  const [isDemoRunning, setIsDemoRunning] = useState(false);
  const [isResetting, setIsResetting] = useState(false);
  const [demoModalOpen, setDemoModalOpen] = useState(false);
  const [demoTimeline, setDemoTimeline] = useState<any[]>([]);
  const [demoResult, setDemoResult] = useState<any | null>(null);

  const fetchData = async () => {
    try {
      const [uData, aData, jData] = await Promise.all([
        api.get<{ users: any[] }>('/api/auth/users'),
        api.get<{ alerts: AccountAlert[] }>('/api/account-security/alerts'),
        api.get<{ joinCode: string }>('/api/organizations/join-code').catch(() => ({ joinCode: '' }))
      ]);

      if (uData && uData.users) {
        setUsers(uData.users);
      }
      if (aData && aData.alerts) {
        setAlerts(aData.alerts);
      }
      if (jData && jData.joinCode) {
        setJoinCode(jData.joinCode);
      }
    } catch (err) {
      console.error('Error fetching account security data:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleCopyJoinCode = () => {
    if (!joinCode) return;
    navigator.clipboard.writeText(joinCode);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const handleRegenerateJoinCode = async () => {
    if (!window.confirm('Regenerate organization join code? The previous code will become invalid immediately for new user registrations.')) return;
    try {
      const res = await api.post<{ success: boolean; joinCode: string }>('/api/organizations/join-code/regenerate', {});
      if (res && res.joinCode) {
        setJoinCode(res.joinCode);
        addNotification('Join Code Regenerated', `New organization join code: ${res.joinCode}`, 'SUCCESS');
      }
    } catch (err: any) {
      addNotification('Error', err.message || 'Failed to regenerate join code', 'ALERT');
    }
  };

  const handleApproveUser = async (user: any) => {
    try {
      const res = await api.post<{ success: boolean; message: string }>(`/api/account-security/users/${user.id}/approve`, {});
      addNotification('User Approved', res.message || `Account for ${user.name} approved.`, 'SUCCESS');
      await fetchData();
    } catch (err: any) {
      addNotification('Approval Failed', err.message || 'Failed to approve user', 'ALERT');
    }
  };

  const handleToggleUserRole = async (user: any) => {
    const newRole = user.role === 'admin' ? 'user' : 'admin';
    const actionLabel = newRole === 'admin' ? 'promote' : 'demote';
    if (!window.confirm(`Are you sure you want to ${actionLabel} ${user.name} to ${newRole.toUpperCase()}?`)) return;

    try {
      const res = await api.post<{ success: boolean; message: string }>(`/api/account-security/users/${user.id}/role`, { role: newRole });
      addNotification('User Role Updated', res.message || `User role updated to ${newRole}.`, 'SUCCESS');
      await fetchData();
    } catch (err: any) {
      addNotification('Role Update Failed', err.message || 'Failed to update user role', 'ALERT');
    }
  };

  useEffect(() => {
    fetchData();
    // 3-second polling ensures multi-tab and page refresh resilience
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, [activeOrg]);

  const handleSimulateAttack = async () => {
    if (!selectedSimUser) return;
    setIsSimulating(true);
    try {
      const data = await api.post<any>('/api/account-security/simulate', {
        userId: selectedSimUser,
        attackType: selectedAttackType
      });
      setIsSimulating(false);
      setIsSimModalOpen(false);

      const attackLabel = selectedAttackType === 'ALL'
        ? 'Multi-Vector Attack'
        : selectedAttackType.replace(/_/g, ' ');

      addNotification(
        `🚨 ${attackLabel} Simulated`,
        `Simulated attack injected on user. Alert created with ${data.alert?.confidence}% confidence.`,
        'ALERT',
        `/account-security/${selectedSimUser}`
      );
      await fetchData();
    } catch (err: any) {
      console.error('Simulation error:', err);
      setIsSimulating(false);
      addNotification('Simulation Failed', err.message || 'Simulation failed', 'ALERT');
    }
  };

  const handleRunAccountAttackDemo = async () => {
    setIsDemoRunning(true);
    setDemoModalOpen(true);
    setDemoTimeline([]);
    setDemoResult(null);

    try {
      const data = await api.post<any>('/api/account-security/demo-attack-run', {});
      setIsDemoRunning(false);

      setDemoResult(data);
      setDemoTimeline(data.timeline || []);
      addNotification(
        '🎉 Account Attack Demo Completed',
        'Executed 8-stage sequence: attack -> alert -> remote fix -> user notice -> risk drop -> pattern shared -> peer warning -> audit verified.',
        'SUCCESS',
        '/account-security'
      );
      await fetchData();
    } catch (err: any) {
      setIsDemoRunning(false);
      addNotification('Demo Error', err.message, 'ALERT');
    }
  };

  const handleResetBaseline = async () => {
    setIsResetting(true);
    try {
      await api.post('/api/account-security/demo-reset', {});
      setIsResetting(false);
      addNotification(
        'Baseline State Restored',
        'Prototype reset to baseline. User accounts, sessions, and risk scores returned to clean state.',
        'SUCCESS'
      );
      await fetchData();
    } catch (err: any) {
      setIsResetting(false);
      addNotification('Reset Error', err.message, 'ALERT');
    }
  };

  // Map user with their latest alert and risk score
  const augmentedUsers = users.map((u) => {
    const activeAlert = alerts.find((a) => a.userId === u.id && a.status !== 'Remediated');
    const risk = activeAlert ? activeAlert.accountRiskScore : u.role === 'admin' ? 22 : 15;
    const isUnderAttack = Boolean(activeAlert);
    return {
      ...u,
      activeAlert,
      risk,
      isUnderAttack
    };
  });

  // Filter and Sort
  const filteredUsers = augmentedUsers
    .filter((u) => {
      const matchesSearch =
        u.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        u.email.toLowerCase().includes(searchQuery.toLowerCase());

      const matchesStatus =
        statusFilter === 'ALL' ||
        (statusFilter === 'ACTIVE' && u.status === 'active' && !u.isUnderAttack) ||
        (statusFilter === 'ATTACK' && u.isUnderAttack) ||
        (statusFilter === 'LOCKED' && u.status === 'locked') ||
        (statusFilter === 'RESET' && (u.status === 'reset_required' || u.mustReset));

      const matchesPrivilege =
        privilegeFilter === 'ALL' || u.privilegeLevel === privilegeFilter;

      return matchesSearch && matchesStatus && matchesPrivilege;
    })
    .sort((a, b) => {
      return sortOrder === 'DESC' ? b.risk - a.risk : a.risk - b.risk;
    });

  const totalUsers = users.length;
  const underAttackCount = augmentedUsers.filter((u) => u.isUnderAttack).length;
  const lockedCount = users.filter((u) => u.status === 'locked').length;
  const healthyCount = users.filter((u) => u.status === 'active' && !u.isUnderAttack).length;

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Top Banner Header */}
      <div className="bg-[#0F1420] border border-slate-800 rounded-2xl p-6 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-80 h-80 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 relative z-10">
          <div>
            <div className="flex items-center space-x-3 mb-1">
              <span className="p-2 rounded-xl bg-cyan-950/60 border border-cyan-800/40 text-cyan-400">
                <UserCheck className="w-6 h-6" />
              </span>
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white flex items-center space-x-2">
                  <span>Account Security Console</span>
                  <span className="text-[10px] bg-cyan-950/80 text-cyan-400 border border-cyan-800/50 px-2 py-0.5 rounded font-mono">
                    MODULE 8
                  </span>
                </h1>
                <p className="text-xs text-slate-400 font-mono mt-0.5 flex items-center space-x-2">
                  <span>Identity Governance & Account-Level Remote Remediation</span>
                  <span>•</span>
                  <span className="text-cyan-400">{activeOrg?.name || 'Bank A'}</span>
                </p>
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            {/* Run Account Attack Demo Button */}
            <button
              onClick={handleRunAccountAttackDemo}
              disabled={isDemoRunning}
              className="px-3.5 py-2 bg-gradient-to-r from-purple-600 via-indigo-600 to-cyan-600 hover:from-purple-500 hover:to-cyan-500 text-white text-xs font-bold rounded-lg shadow-lg shadow-purple-900/40 flex items-center space-x-1.5 transition-all"
            >
              <Sparkles className="w-3.5 h-3.5 text-yellow-300 animate-spin" />
              <span>{isDemoRunning ? 'Running Demo...' : 'Run Account Attack Demo'}</span>
            </button>

            {/* Simulate Single Attack */}
            <button
              onClick={() => {
                if (users.length > 0 && !selectedSimUser) {
                  const targetUser = users.find((u) => u.email === 'attack_target@banka.com') || users.find((u) => u.role === 'user') || users[0];
                  setSelectedSimUser(targetUser.id);
                }
                setIsSimModalOpen(true);
              }}
              className="px-3.5 py-2 bg-rose-950/70 hover:bg-rose-900/90 border border-rose-600/50 text-rose-300 text-xs font-semibold rounded-lg flex items-center space-x-1.5 transition-all"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Simulate Attack</span>
            </button>

            {/* Reset Baseline */}
            <button
              onClick={handleResetBaseline}
              disabled={isResetting}
              className="px-3 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 hover:text-amber-300 text-xs font-medium rounded-lg flex items-center space-x-1.5 transition-all"
              title="Reset Database to Clean Baseline"
            >
              <RotateCcw className={`w-3.5 h-3.5 ${isResetting ? 'animate-spin text-amber-400' : ''}`} />
              <span>Reset</span>
            </button>

            <button
              onClick={fetchData}
              className="p-2 bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 rounded-lg text-slate-300 transition-colors"
              title="Refresh"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#0F1420] border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Total Accounts</span>
            <div className="text-2xl font-bold text-white mt-0.5 font-mono">{totalUsers}</div>
            <span className="text-[10px] text-slate-500">Fleet managed in {activeOrg?.id}</span>
          </div>
          <Users className="w-8 h-8 text-slate-500/60" />
        </div>

        <div className={`border rounded-xl p-4 flex items-center justify-between transition-all ${
          underAttackCount > 0
            ? 'bg-rose-950/20 border-rose-500/50 shadow-lg shadow-rose-950/20'
            : 'bg-[#0F1420] border-slate-800'
        }`}>
          <div>
            <span className="text-[11px] font-semibold text-rose-400 uppercase tracking-wider flex items-center space-x-1">
              {underAttackCount > 0 && <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping mr-1" />}
              <span>Under Attack</span>
            </span>
            <div className="text-2xl font-bold text-rose-300 mt-0.5 font-mono">{underAttackCount}</div>
            <span className="text-[10px] text-rose-400/80">Active hostile alerts</span>
          </div>
          <ShieldAlert className="w-8 h-8 text-rose-400" />
        </div>

        <div className="bg-[#0F1420] border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Locked Accounts</span>
            <div className="text-2xl font-bold text-white mt-0.5 font-mono">{lockedCount}</div>
            <span className="text-[10px] text-slate-500">Isolated by SOC admin</span>
          </div>
          <Lock className="w-8 h-8 text-amber-500/60" />
        </div>

        <div className="bg-[#0F1420] border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Healthy Accounts</span>
            <div className="text-2xl font-bold text-emerald-400 mt-0.5 font-mono">{healthyCount}</div>
            <span className="text-[10px] text-emerald-500/80">Normal authentication baseline</span>
          </div>
          <ShieldCheck className="w-8 h-8 text-emerald-400" />
        </div>
      </div>

      {/* Organization Join Code & Employee Onboarding Card */}
      <div className="bg-[#0F1420] border border-cyan-900/40 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-lg shadow-cyan-950/20">
        <div className="flex items-start sm:items-center space-x-3.5">
          <div className="p-2.5 bg-cyan-950 border border-cyan-800/80 rounded-xl text-cyan-400 shrink-0">
            <Building2 className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-200">Organization Join Code</span>
              <span className="text-[10px] bg-cyan-950 text-cyan-400 border border-cyan-800 px-2 py-0.5 rounded font-mono">SELF-SERVICE</span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Employees can self-register their accounts with this join code to automatically bind to <span className="text-cyan-300 font-semibold">{activeOrg?.name || 'Bank A'}</span>.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2 shrink-0">
          <div className="px-3.5 py-1.5 bg-[#0B0F17] border border-cyan-500/50 rounded-lg text-sm font-mono font-bold text-cyan-300 tracking-wider">
            {joinCode || 'BANK-A01'}
          </div>
          <button
            onClick={handleCopyJoinCode}
            className="px-3 py-1.5 bg-cyan-950 hover:bg-cyan-900 border border-cyan-700 text-cyan-300 rounded-lg text-xs font-semibold transition flex items-center space-x-1.5"
          >
            {copiedCode ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Share2 className="w-3.5 h-3.5" />}
            <span>{copiedCode ? 'Copied' : 'Copy'}</span>
          </button>
          <button
            onClick={handleRegenerateJoinCode}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 rounded-lg text-xs font-semibold transition flex items-center space-x-1.5"
            title="Regenerate Join Code"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Regenerate</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#0F1420] border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex-1 max-w-md relative">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search account by user name or email..."
            className="w-full bg-[#0B0F17] border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Status Filter */}
          <div className="flex items-center space-x-1 bg-[#0B0F17] p-1 rounded-lg border border-slate-800 text-[11px]">
            <button
              onClick={() => setStatusFilter('ALL')}
              className={`px-2.5 py-1 rounded transition-colors ${
                statusFilter === 'ALL' ? 'bg-slate-700 text-white font-medium' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              All ({augmentedUsers.length})
            </button>
            <button
              onClick={() => setStatusFilter('ATTACK')}
              className={`px-2.5 py-1 rounded transition-colors flex items-center space-x-1 ${
                statusFilter === 'ATTACK' ? 'bg-rose-950 text-rose-300 font-medium' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <span>Attacked</span>
              {underAttackCount > 0 && (
                <span className="w-4 h-4 rounded-full bg-rose-500 text-[9px] text-white flex items-center justify-center font-bold">
                  {underAttackCount}
                </span>
              )}
            </button>
            <button
              onClick={() => setStatusFilter('LOCKED')}
              className={`px-2.5 py-1 rounded transition-colors ${
                statusFilter === 'LOCKED' ? 'bg-amber-950 text-amber-300 font-medium' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Locked ({lockedCount})
            </button>
            <button
              onClick={() => setStatusFilter('ACTIVE')}
              className={`px-2.5 py-1 rounded transition-colors ${
                statusFilter === 'ACTIVE' ? 'bg-emerald-950 text-emerald-300 font-medium' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Healthy
            </button>
          </div>

          {/* Privilege Filter */}
          <select
            value={privilegeFilter}
            onChange={(e) => setPrivilegeFilter(e.target.value)}
            className="bg-[#0B0F17] border border-slate-800 text-slate-300 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Privileges</option>
            <option value="ADMIN">ADMIN</option>
            <option value="ELEVATED">ELEVATED</option>
            <option value="STANDARD">STANDARD</option>
          </select>

          {/* Sort Order */}
          <button
            onClick={() => setSortOrder(sortOrder === 'DESC' ? 'ASC' : 'DESC')}
            className="px-2.5 py-1.5 bg-[#0B0F17] hover:bg-slate-800 border border-slate-800 rounded-lg text-slate-300 text-xs flex items-center space-x-1.5 transition-colors"
            title="Sort by Risk"
          >
            <ArrowUpDown className="w-3.5 h-3.5" />
            <span>{sortOrder === 'DESC' ? 'Highest Risk' : 'Lowest Risk'}</span>
          </button>
        </div>
      </div>

      {/* Fleet Accounts Table */}
      <div className="bg-[#0F1420] border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#0B0F17] text-slate-400 border-b border-slate-800 font-medium">
              <tr>
                <th className="py-3 px-4">User Account</th>
                <th className="py-3 px-4">Account Status</th>
                <th className="py-3 px-4">Privilege Level</th>
                <th className="py-3 px-4">MFA Policy</th>
                <th className="py-3 px-4">Account Risk</th>
                <th className="py-3 px-4">Active Threat / Alert</th>
                <th className="py-3 px-4 text-right">SOC Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {filteredUsers.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 text-xs">
                    No accounts found matching current search and filter criteria.
                  </td>
                </tr>
              ) : (
                filteredUsers.map((u) => {
                  const isLocked = u.status === 'locked';
                  const isReset = u.status === 'reset_required' || u.mustReset;
                  const isAttack = u.isUnderAttack;

                  return (
                    <tr
                      key={u.id}
                      className={`hover:bg-slate-800/40 transition-colors ${
                        isAttack ? 'bg-rose-950/10' : ''
                      }`}
                    >
                      {/* User Account */}
                      <td className="py-3 px-4">
                        <div className="flex items-center space-x-3">
                          <div className={`w-8 h-8 rounded-lg flex items-center justify-center font-bold text-xs uppercase ${
                            isAttack
                              ? 'bg-rose-950 text-rose-300 border border-rose-500/50'
                              : 'bg-slate-800 text-slate-300 border border-slate-700'
                          }`}>
                            {u.name.slice(0, 2)}
                          </div>
                          <div>
                            <div className="font-semibold text-slate-100 flex items-center space-x-1.5">
                              <span>{u.name}</span>
                              {u.email === 'attack_target@banka.com' && (
                                <span className="text-[9px] bg-rose-950/90 text-rose-300 border border-rose-600/60 px-1.5 py-0.2 rounded font-mono font-bold tracking-wide">
                                  RED TEAM TARGET
                                </span>
                              )}
                              {u.role === 'admin' && (
                                <span className="text-[9px] bg-purple-950/80 text-purple-300 border border-purple-800/50 px-1.5 py-0.2 rounded font-mono">
                                  ADMIN
                                </span>
                              )}
                            </div>
                            <div className="text-[11px] text-slate-400 font-mono">{u.email}</div>
                          </div>
                        </div>
                      </td>

                      {/* Account Status */}
                      <td className="py-3 px-4">
                        {isAttack ? (
                          <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold bg-rose-950/90 text-rose-300 border border-rose-500 animate-pulse">
                            <span className="w-1.5 h-1.5 rounded-full bg-rose-400 animate-ping" />
                            <span>UNDER ATTACK</span>
                          </span>
                        ) : isLocked ? (
                          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-rose-950/80 text-rose-300 border border-rose-800/50">
                            <Lock className="w-3 h-3" />
                            <span>LOCKED</span>
                          </span>
                        ) : isReset ? (
                          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-amber-950/80 text-amber-300 border border-amber-800/50">
                            <KeyRound className="w-3 h-3" />
                            <span>RESET REQ</span>
                          </span>
                        ) : u.status === 'pending' ? (
                          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-amber-950/80 text-amber-300 border border-amber-800/50">
                            <Clock className="w-3 h-3" />
                            <span>PENDING APPROVAL</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-950/60 text-emerald-300 border border-emerald-800/40">
                            <CheckCircle2 className="w-3 h-3" />
                            <span>ACTIVE</span>
                          </span>
                        )}
                      </td>

                      {/* Privilege Level */}
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold ${
                          u.privilegeLevel === 'ADMIN'
                            ? 'bg-purple-950/80 text-purple-300 border border-purple-800/50'
                            : u.privilegeLevel === 'ELEVATED'
                            ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-800/50'
                            : 'bg-slate-800 text-slate-400 border border-slate-700/60'
                        }`}>
                          {u.privilegeLevel || 'STANDARD'}
                        </span>
                      </td>

                      {/* MFA Policy */}
                      <td className="py-3 px-4">
                        {u.mfaRequired ? (
                          <span className="text-[11px] text-amber-300 font-mono flex items-center space-x-1">
                            <Shield className="w-3 h-3 text-amber-400" />
                            <span>Enforced</span>
                          </span>
                        ) : (
                          <span className="text-[11px] text-slate-500 font-mono">Optional</span>
                        )}
                      </td>

                      {/* Account Risk Score */}
                      <td className="py-3 px-4">
                        <div className="flex items-center space-x-2">
                          <div className={`w-8 text-center font-mono font-bold text-xs ${
                            u.risk >= 80 ? 'text-rose-400' : u.risk >= 65 ? 'text-amber-400' : u.risk >= 45 ? 'text-cyan-400' : 'text-emerald-400'
                          }`}>
                            {u.risk}
                          </div>
                          <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${
                                u.risk >= 80 ? 'bg-rose-500' : u.risk >= 65 ? 'bg-amber-500' : u.risk >= 45 ? 'bg-cyan-500' : 'bg-emerald-500'
                              }`}
                              style={{ width: `${u.risk}%` }}
                            />
                          </div>
                        </div>
                      </td>

                      {/* Active Threat / Alert */}
                      <td className="py-3 px-4 max-w-xs truncate">
                        {u.activeAlert ? (
                          <div className="text-[11px] text-rose-300 truncate" title={u.activeAlert.summary}>
                            <span className="font-semibold text-rose-400">{u.activeAlert.matchedRules.length} Rule(s):</span>{' '}
                            {u.activeAlert.title}
                          </div>
                        ) : (
                          <span className="text-[11px] text-slate-500 font-mono">No active incidents</span>
                        )}
                      </td>

                      {/* SOC Actions */}
                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end space-x-1.5">
                          {u.status === 'pending' && (
                            <button
                              onClick={() => handleApproveUser(u)}
                              className="px-2 py-1 rounded bg-emerald-950 hover:bg-emerald-900 border border-emerald-600/60 text-emerald-300 text-xs font-semibold flex items-center space-x-1 transition"
                              title="Approve user registration"
                            >
                              <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                              <span>Approve</span>
                            </button>
                          )}
                          {u.email === 'attack_target@banka.com' && (
                            <button
                              onClick={() => {
                                setSelectedSimUser(u.id);
                                setIsSimModalOpen(true);
                              }}
                              className="px-2 py-1 rounded bg-rose-950/80 hover:bg-rose-900 border border-rose-600/60 text-rose-300 text-xs font-semibold flex items-center space-x-1 transition"
                              title="Simulate Attack On This Red Team Sandbox Account"
                            >
                              <Play className="w-3 h-3 fill-current" />
                              <span>Attack</span>
                            </button>
                          )}
                          <button
                            onClick={() => handleToggleUserRole(u)}
                            className="px-2 py-1 rounded bg-slate-800/80 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-cyan-300 text-[11px] font-mono transition"
                            title={u.role === 'admin' ? 'Demote to standard user' : 'Promote to SOC administrator'}
                          >
                            {u.role === 'admin' ? 'Demote' : 'Promote'}
                          </button>
                          <button
                            onClick={() => navigate(`/account-security/${u.id}`)}
                            className={`px-2.5 py-1 rounded text-xs font-semibold flex items-center space-x-1 transition-all ${
                              isAttack
                                ? 'bg-rose-600 hover:bg-rose-500 text-white shadow-lg shadow-rose-900/40 animate-pulse'
                                : 'bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700'
                            }`}
                          >
                            <Eye className="w-3.5 h-3.5" />
                            <span>{isAttack ? 'Fix Attack' : 'Detail'}</span>
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Simulation Modal (SIMULATION-ONLY) */}
      {isSimModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-[#0F1420] border border-rose-500/50 rounded-2xl max-w-md w-full p-6 space-y-5 shadow-2xl relative">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2 text-rose-400">
                <Play className="w-5 h-5 fill-current" />
                <h3 className="font-bold text-sm uppercase tracking-wider text-white">Simulate Account Attack</h3>
              </div>
              <span className="text-[10px] bg-rose-950 text-rose-300 border border-rose-800 px-2 py-0.5 rounded font-mono">
                DEMO ONLY
              </span>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              Inject a deterministic account intrusion on the target account to test SOC detection, risk scoring, explainability waterfalls, and instant remote remediation.
            </p>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">Target Account</label>
              <select
                value={selectedSimUser}
                onChange={(e) => setSelectedSimUser(e.target.value)}
                className="w-full bg-[#0B0F17] border border-slate-700 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-rose-500"
              >
                {users.map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.email === 'attack_target@banka.com' ? '🎯 [SANDBOX TARGET] ' : ''}
                    {u.name} ({u.email}) - {u.role.toUpperCase()}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">Attack Vector / Intrusion Type</label>
              <select
                value={selectedAttackType}
                onChange={(e) => setSelectedAttackType(e.target.value)}
                className="w-full bg-[#0B0F17] border border-slate-700 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-rose-500"
              >
                <option value="ALL">⚡ All Multi-Vector Intrusion (Combined 6-Vector Kill Chain)</option>
                <option value="BRUTE_FORCE">🔑 Credential Stuffing Streak (5 Rapid Failed Logins - Rule 1)</option>
                <option value="CRACKED_CREDENTIALS">🔓 Cracked Credentials / Account Takeover (ATO - Rule 2)</option>
                <option value="ROGUE_DEVICE">💻 Rogue Hardware / Automation Client (Python Scraper - Rule 3)</option>
                <option value="IMPOSSIBLE_TRAVEL">🌍 Anomalous Offshore Location / Impossible Velocity (Rule 4)</option>
                <option value="PRIVILEGE_ESCALATION">🛡️ Unauthorized Administrative Privilege Escalation (Rule 5)</option>
                <option value="DATA_EXFILTRATION">📦 High-Volume Sensitive Data Exfiltration (4.5 GB - Rule 6)</option>
              </select>
              <p className="text-[11px] text-slate-400 mt-1 font-mono">
                {selectedAttackType === 'ALL' && 'Simulates full kill-chain across all 6 threat rules. Confidence: 95%.'}
                {selectedAttackType === 'BRUTE_FORCE' && 'Injects 5 rapid failed password attempts in 60s, triggering rate limiting & brute-force alarm.'}
                {selectedAttackType === 'CRACKED_CREDENTIALS' && 'Simulates successful authentication directly following a failed attempt streak.'}
                {selectedAttackType === 'ROGUE_DEVICE' && 'Simulates sign-in from untrusted Python-Requests adversary automation fingerprint.'}
                {selectedAttackType === 'IMPOSSIBLE_TRAVEL' && 'Simulates immediate login origin jump to Frankfurt, Germany.'}
                {selectedAttackType === 'PRIVILEGE_ESCALATION' && 'Simulates standard user attempting unauthorized elevation to ADMIN.'}
                {selectedAttackType === 'DATA_EXFILTRATION' && 'Simulates 4.5 GB bulk CIF record egress exceeding 95th percentile baseline.'}
              </p>
            </div>

            <div className="flex items-center justify-end space-x-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setIsSimModalOpen(false)}
                className="px-3.5 py-1.5 text-xs text-slate-400 hover:text-slate-200"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={isSimulating}
                onClick={handleSimulateAttack}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white font-semibold text-xs rounded-lg shadow-lg shadow-rose-900/40 flex items-center space-x-2"
              >
                <span>{isSimulating ? 'Injecting Sequence...' : 'Launch Attack Simulation'}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Phase 6: Account Attack Demo Execution Modal */}
      {demoModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md animate-fadeIn">
          <div className="bg-[#0F1420] border border-cyan-500/50 rounded-3xl max-w-3xl w-full p-6 sm:p-7 space-y-6 shadow-2xl relative max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center space-x-3">
                <span className="p-2.5 rounded-2xl bg-gradient-to-br from-purple-600 to-cyan-600 text-white shadow-lg shadow-purple-900/40">
                  <Sparkles className="w-6 h-6 animate-spin" />
                </span>
                <div>
                  <h3 className="font-bold text-base uppercase tracking-tight text-white flex items-center space-x-2">
                    <span>Account Attack & Remote Fix Demo</span>
                    <span className="text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-800 px-2 py-0.5 rounded font-mono">
                      REPRODUCIBLE E2E NARRATIVE
                    </span>
                  </h3>
                  <p className="text-xs text-slate-400 font-mono mt-0.5">
                    Attack on user → Admin alert → Admin fix → User notice → Risk drops → Pattern shared → Peer warning → DLT ledger
                  </p>
                </div>
              </div>

              <button
                type="button"
                onClick={() => setDemoModalOpen(false)}
                className="text-slate-400 hover:text-white p-1 rounded-lg"
              >
                ✕
              </button>
            </div>

            {/* Stepper Timeline */}
            <div className="space-y-3">
              {isDemoRunning ? (
                <div className="py-12 text-center space-y-3">
                  <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin mx-auto" />
                  <p className="text-xs text-cyan-300 font-mono">
                    Executing automated 8-stage account security narrative sequence across engines...
                  </p>
                </div>
              ) : (
                <div className="space-y-2.5">
                  {demoTimeline.map((step) => (
                    <div
                      key={step.step}
                      className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 flex items-start space-x-3 text-xs font-mono"
                    >
                      <div className="w-6 h-6 rounded-lg bg-emerald-950 border border-emerald-500/60 text-emerald-300 flex items-center justify-center font-bold shrink-0 mt-0.5">
                        ✓
                      </div>
                      <div className="flex-1 space-y-0.5">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-slate-200">
                            Step {step.step}: {step.title}
                          </span>
                          <span className="text-[10px] text-slate-500">
                            {new Date(step.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 font-sans">{step.description}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Telemetry Summary Cards */}
            {demoResult && (
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2 text-xs font-mono">
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                  <div className="text-[10px] text-slate-500">Unified Org Risk</div>
                  <div className="text-emerald-400 font-bold text-base mt-0.5">
                    {demoResult.updatedOrgRisk} <span className="text-xs font-normal text-slate-500">/ 100</span>
                  </div>
                  <div className="text-[10px] text-slate-400 mt-0.5">Risk drop verified live</div>
                </div>

                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                  <div className="text-[10px] text-slate-500">DLT Ledger Anchor</div>
                  <div className="text-purple-300 font-bold text-base mt-0.5">
                    Block #{demoResult.dltBlock?.blockNumber}
                  </div>
                  <div className="text-[10px] text-emerald-400 mt-0.5">Consensus: CONFIRMED</div>
                </div>

                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                  <div className="text-[10px] text-slate-500">Audit Hash-Chain</div>
                  <div className="text-cyan-400 font-bold text-base mt-0.5">
                    {demoResult.auditVerification?.totalVerified} Records
                  </div>
                  <div className="text-[10px] text-emerald-400 mt-0.5">SHA-256 Intact: 100%</div>
                </div>
              </div>
            )}

            {/* Footer Action Buttons */}
            <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={handleResetBaseline}
                disabled={isResetting}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-xl flex items-center space-x-1.5 transition-colors"
              >
                <RotateCcw className={`w-3.5 h-3.5 ${isResetting ? 'animate-spin text-amber-400' : ''}`} />
                <span>Reset to Clean Baseline</span>
              </button>

              <div className="flex items-center space-x-2">
                <button
                  type="button"
                  onClick={() => {
                    setDemoModalOpen(false);
                    navigate('/account-security/usr-bank-alice');
                  }}
                  className="px-4 py-2 bg-cyan-950 hover:bg-cyan-900 border border-cyan-700/60 text-cyan-300 text-xs font-semibold rounded-xl flex items-center space-x-1.5"
                >
                  <span>Inspect Alice Account</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </button>

                <button
                  type="button"
                  onClick={() => setDemoModalOpen(false)}
                  className="px-4 py-2 bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 text-slate-950 text-xs font-bold rounded-xl shadow-lg transition-all"
                >
                  Done
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
