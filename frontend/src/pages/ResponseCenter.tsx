import React, { useState, useMemo } from 'react';
import {
  Zap,
  CheckCircle2,
  Play,
  ShieldCheck,
  TrendingDown,
  AlertTriangle,
  ArrowRight,
  Plus,
  Clock,
  Building2,
  Shield,
  RefreshCw,
  Sparkles,
  Filter,
  Timer
} from 'lucide-react';
import { useApp } from '../context/AppContext';

export const ResponseCenter: React.FC = () => {
  const { responseActions, executeResponseAction, activeOrg, riskData, addNotification, addResponseAction } = useApp();
  const [executingId, setExecutingId] = useState<string | null>(null);
  const [remediationMsg, setRemediationMsg] = useState<string | null>(null);
  const [selectedFilter, setSelectedFilter] = useState<'ALL' | 'QUICK_WINS' | 'PENDING'>('ALL');

  // Custom action state
  const [customTitle, setCustomTitle] = useState('');
  const [customPts, setCustomPts] = useState(10);
  const [customPriority, setCustomPriority] = useState<'CRITICAL' | 'HIGH' | 'MEDIUM'>('HIGH');
  const [customEffort, setCustomEffort] = useState<'Low' | 'Medium' | 'High'>('Low');

  // Filter response actions to ONLY show actions for the active organization
  const orgActions = useMemo(() => {
    if (!activeOrg) return [];
    return responseActions.filter((a) => a.orgId === activeOrg.id);
  }, [responseActions, activeOrg]);

  const quickWinCount = orgActions.filter((a) => a.isQuickWin || a.effort === 'Low').length;
  const completedCount = orgActions.filter((a) => a.status === 'Completed').length;
  const pendingCount = orgActions.filter((a) => a.status === 'Pending').length;
  const inProgressCount = orgActions.filter((a) => a.status === 'In Progress').length;

  const filteredActions = useMemo(() => {
    return orgActions.filter((a) => {
      if (selectedFilter === 'QUICK_WINS') return a.isQuickWin || a.effort === 'Low';
      if (selectedFilter === 'PENDING') return a.status === 'Pending';
      return true;
    });
  }, [orgActions, selectedFilter]);

  // Primary incident ID for new actions
  const primaryIncidentId = orgActions[0]?.incidentId || 'inc-1';

  const handleActionClick = async (actionId: string, incidentId: string, statusType: 'In Progress' | 'Completed') => {
    setExecutingId(actionId);
    try {
      const res = await executeResponseAction(actionId, incidentId, statusType);
      if (res.riskReduction && statusType === 'Completed') {
        setRemediationMsg(
          `✅ Action Executed! Organization risk reduced from ${res.riskReduction.previousScore} → ${res.riskReduction.newScore} (-${res.riskReduction.pointsReduced} pts)!`
        );
      }
    } catch (e) {
      console.error('Response action error:', e);
    }
    setExecutingId(null);
  };

  const handleAddCustomAction = () => {
    if (!customTitle.trim() || !activeOrg) return;
    const isQuick = customEffort === 'Low' && customPts >= 8;
    const newAct = {
      id: `act-${Date.now()}`,
      incidentId: primaryIncidentId,
      orgId: activeOrg.id,
      title: customTitle.trim(),
      priority: customPriority,
      reason: 'Custom response action created by security operator.',
      estimatedRiskReduction: customPts,
      status: 'Pending' as const,
      effort: customEffort,
      estimatedTime: customEffort === 'Low' ? '30 mins' : customEffort === 'Medium' ? '4 hours' : '2 days',
      isQuickWin: isQuick
    };
    addResponseAction(newAct);
    setCustomTitle('');
    addNotification('Response Action Created', `Added custom remediation playbook: ${newAct.title}`, 'SUCCESS', '/response-center');
  };

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 sm:space-y-8 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-100 uppercase">RESPONSE CENTER</h1>
            <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 text-[10px] font-mono border border-emerald-800 font-bold">
              PLAYBOOK EXECUTION
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Prioritized automated remediation playbooks with quantifiable effort estimates and instant risk reduction.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 sm:gap-3 w-full sm:w-auto">
          {/* Active Org Badge */}
          <div className="px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 flex items-center space-x-2">
            <Building2 className="w-4 h-4 text-cyan-400" />
            <div>
              <div className="text-[10px] font-mono text-slate-500 uppercase">Active Organization</div>
              <div className="text-xs font-bold text-slate-200">{activeOrg?.name || 'None Selected'}</div>
            </div>
          </div>

          <div className="px-3.5 py-1.5 rounded-xl bg-slate-900 border border-slate-800 flex items-center space-x-2.5">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <div>
              <div className="text-[10px] font-mono text-slate-500 uppercase">Current Risk Score</div>
              <div className="text-xs font-bold text-slate-200 font-mono">
                {riskData?.overallRiskScore ?? activeOrg?.riskScore ?? 84} / 100
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Remediation Feedback Alert */}
      {remediationMsg && (
        <div className="p-4 rounded-xl bg-emerald-950/80 border border-emerald-500/80 text-emerald-200 text-xs font-mono font-bold flex items-center justify-between animate-fadeIn shadow-lg shadow-emerald-950/60">
          <div className="flex items-center space-x-2">
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
            <span>{remediationMsg}</span>
          </div>
          <button
            onClick={() => setRemediationMsg(null)}
            className="text-xs text-slate-400 hover:text-slate-200 underline"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* 4 Overview Stat Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4 font-mono">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="text-[10px] text-slate-500 uppercase font-bold">Total Playbook Actions</div>
          <div className="text-xl sm:text-2xl font-bold text-cyan-400 mt-1">{orgActions.length}</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-emerald-800/80">
          <div className="text-[10px] text-emerald-400 uppercase font-bold flex items-center space-x-1">
            <Sparkles className="w-3 h-3" />
            <span>Quick Wins Available</span>
          </div>
          <div className="text-xl sm:text-2xl font-bold text-emerald-400 mt-1">{quickWinCount}</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="text-[10px] text-slate-500 uppercase font-bold">In Progress</div>
          <div className="text-xl sm:text-2xl font-bold text-amber-400 mt-1">{inProgressCount}</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="text-[10px] text-slate-500 uppercase font-bold">Completed / Remediated</div>
          <div className="text-xl sm:text-2xl font-bold text-emerald-400 mt-1">{completedCount}</div>
        </div>
      </div>

      {/* Add Custom Action Form */}
      <div className="glass-panel p-5 rounded-2xl border border-cyan-500/30 space-y-3">
        <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
            <Plus className="w-4 h-4 text-cyan-400" />
            <span>CREATE CUSTOM REMEDIATION PLAYBOOK ACTION</span>
          </h3>
          <span className="text-[10px] font-mono text-slate-500">For: {activeOrg?.name}</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-3 text-xs">
          <div className="sm:col-span-2">
            <label className="block text-slate-400 font-mono mb-1 text-[11px]">Action Title</label>
            <input
              type="text"
              placeholder="e.g. Enforce IP Whitelisting on Core Database Port 1521..."
              value={customTitle}
              onChange={(e) => setCustomTitle(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleAddCustomAction()}
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-slate-400 font-mono mb-1 text-[11px]">Priority</label>
            <select
              value={customPriority}
              onChange={(e) => setCustomPriority(e.target.value as any)}
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
            >
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
            </select>
          </div>

          <div>
            <label className="block text-slate-400 font-mono mb-1 text-[11px]">Effort Level</label>
            <select
              value={customEffort}
              onChange={(e) => setCustomEffort(e.target.value as any)}
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
            >
              <option value="Low">Low (~30m)</option>
              <option value="Medium">Medium (~4h)</option>
              <option value="High">High (~2d)</option>
            </select>
          </div>

          <div>
            <label className="block text-slate-400 font-mono mb-1 text-[11px]">Risk Reduction</label>
            <div className="flex items-center space-x-2">
              <input
                type="number"
                value={customPts}
                min={1}
                max={30}
                onChange={(e) => setCustomPts(Number(e.target.value))}
                className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
              />
              <button
                onClick={handleAddCustomAction}
                className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs shrink-0 glow-cyan transition-all"
              >
                Add
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Prioritized Action Cards Section with Quick Win Filtering */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div className="flex items-center space-x-2">
            <Zap className="w-4 h-4 text-cyan-400 shrink-0" />
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">
              PRIORITIZED REMEDIATION PLAYBOOK — {activeOrg?.name?.toUpperCase()}
            </h3>
          </div>

          {/* Filter Tabs */}
          <div className="flex items-center space-x-1.5 bg-slate-900 p-1 rounded-xl border border-slate-800 font-mono text-xs">
            <button
              onClick={() => setSelectedFilter('ALL')}
              className={`px-3 py-1 rounded-lg transition-all ${
                selectedFilter === 'ALL'
                  ? 'bg-cyan-500 text-slate-950 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              All ({orgActions.length})
            </button>
            <button
              onClick={() => setSelectedFilter('QUICK_WINS')}
              className={`px-3 py-1 rounded-lg flex items-center space-x-1 transition-all ${
                selectedFilter === 'QUICK_WINS'
                  ? 'bg-emerald-500 text-slate-950 font-bold'
                  : 'text-emerald-400 hover:text-emerald-300'
              }`}
            >
              <Sparkles className="w-3 h-3 shrink-0" />
              <span>Quick Wins ({quickWinCount})</span>
            </button>
            <button
              onClick={() => setSelectedFilter('PENDING')}
              className={`px-3 py-1 rounded-lg transition-all ${
                selectedFilter === 'PENDING'
                  ? 'bg-amber-500 text-slate-950 font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Pending ({pendingCount})
            </button>
          </div>
        </div>

        {filteredActions.length === 0 ? (
          <div className="glass-panel p-12 rounded-2xl border border-slate-800 text-center space-y-3">
            <Shield className="w-10 h-10 text-slate-600 mx-auto" />
            <p className="text-slate-400 font-mono text-sm">No actions matching current filter.</p>
            <button
              onClick={() => setSelectedFilter('ALL')}
              className="px-4 py-1.5 rounded-lg bg-slate-800 text-slate-200 text-xs font-mono hover:bg-slate-700"
            >
              Reset Filter
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-3.5">
            {filteredActions.map((act) => {
              const isCompleted = act.status === 'Completed';
              const isInProgress = act.status === 'In Progress';
              const isExecuting = executingId === act.id;
              const isQuickWin = act.isQuickWin || act.effort === 'Low';
              const effort = act.effort || 'Low';
              const estimatedTime = act.estimatedTime || (effort === 'Low' ? '15 mins' : effort === 'Medium' ? '2 hours' : '1 day');

              return (
                <div
                  key={act.id}
                  className={`p-4 sm:p-5 rounded-2xl border transition-all ${
                    isCompleted
                      ? 'bg-slate-950/40 border-emerald-900/60 opacity-80'
                      : isInProgress
                      ? 'glass-panel border-amber-500/60 shadow-md'
                      : isQuickWin
                      ? 'glass-panel border-emerald-500/50 hover:border-emerald-400 shadow-md ring-1 ring-emerald-500/20'
                      : 'glass-panel border-cyan-500/40 hover:border-cyan-400 shadow-md'
                  }`}
                >
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div className="space-y-1.5 flex-1">
                      <div className="flex items-center space-x-2 flex-wrap gap-1.5">
                        <span
                          className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border ${
                            act.priority === 'CRITICAL'
                              ? 'bg-rose-950 text-rose-400 border-rose-800'
                              : act.priority === 'HIGH'
                              ? 'bg-amber-950 text-amber-400 border-amber-800'
                              : 'bg-blue-950 text-blue-400 border-blue-800'
                          }`}
                        >
                          {act.priority}
                        </span>

                        {/* Quick Win Badge */}
                        {isQuickWin && !isCompleted && (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-700 animate-pulse">
                            <Sparkles className="w-3 h-3 mr-1 text-emerald-400" />
                            QUICK WIN
                          </span>
                        )}

                        {/* Effort & Time Estimate Badge */}
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono text-slate-300 bg-slate-900 border border-slate-800">
                          <Clock className="w-3 h-3 mr-1 text-cyan-400" />
                          Effort: {effort} • {estimatedTime}
                        </span>

                        <span className="text-[11px] font-mono text-emerald-400 font-bold flex items-center">
                          <TrendingDown className="w-3.5 h-3.5 mr-1" />
                          Risk Reduction: -{act.estimatedRiskReduction} pts
                        </span>

                        {isInProgress && (
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold border bg-amber-950 text-amber-400 border-amber-800 animate-pulse">
                            ● IN PROGRESS
                          </span>
                        )}
                      </div>

                      <h4 className="text-sm sm:text-base font-bold text-slate-100">{act.title}</h4>
                      <p className="text-xs text-slate-400 leading-relaxed">{act.reason}</p>
                    </div>

                    <div className="flex items-center space-x-2.5 shrink-0">
                      {isCompleted ? (
                        <span className="flex items-center space-x-1.5 px-4 py-2 rounded-xl bg-emerald-950 text-emerald-400 text-xs font-mono font-bold border border-emerald-800">
                          <CheckCircle2 className="w-4 h-4" />
                          <span>Remediated</span>
                        </span>
                      ) : (
                        <div className="flex items-center space-x-2">
                          <button
                            onClick={() => handleActionClick(act.id, act.incidentId, 'In Progress')}
                            disabled={isExecuting}
                            className="px-3 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 text-xs font-mono font-bold flex items-center space-x-1 transition-all"
                          >
                            {isExecuting ? (
                              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                            ) : (
                              <Clock className="w-3.5 h-3.5" />
                            )}
                            <span className="hidden sm:inline">{isInProgress ? 'In Progress' : 'Queue'}</span>
                          </button>

                          <button
                            onClick={() => handleActionClick(act.id, act.incidentId, 'Completed')}
                            disabled={isExecuting}
                            className="flex items-center space-x-2 px-4 sm:px-5 py-2 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-600 hover:from-emerald-400 hover:to-cyan-500 text-slate-950 font-bold text-xs shadow-lg shadow-emerald-900/30 glow-cyan transition-all disabled:opacity-60"
                          >
                            {isExecuting ? (
                              <RefreshCw className="w-4 h-4 animate-spin" />
                            ) : (
                              <Play className="w-4 h-4 fill-slate-950" />
                            )}
                            <span>{isExecuting ? 'Executing...' : 'Execute Remediation'}</span>
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
