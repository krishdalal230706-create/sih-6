import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  AlertTriangle,
  Radio,
  CheckCircle2,
  Share2,
  TrendingUp,
  Activity,
  ArrowUpRight,
  Zap,
  Lock,
  Layers,
  Building2,
  Play,
  ShieldCheck,
  Database,
  Flame,
  Sparkles
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis
} from 'recharts';
import { useApp } from '../context/AppContext';

export const Overview: React.FC = () => {
  const { activeOrg, riskData, isLoading, executeResponseAction, responseActions, vulnerabilityStats, syncStatus } = useApp();
  const navigate = useNavigate();
  const [executingIdx, setExecutingIdx] = useState<number | null>(null);
  const [topRemediationMsg, setTopRemediationMsg] = useState<string | null>(null);

  const currentRiskScore = riskData?.overallRiskScore ?? activeOrg?.riskScore ?? 84;
  const currentSeverity =
    riskData?.severity ??
    (currentRiskScore >= 80 ? 'CRITICAL' : currentRiskScore >= 65 ? 'HIGH' : currentRiskScore >= 45 ? 'MEDIUM' : 'LOW');
  const scoreColor =
    currentRiskScore >= 80 ? '#f43f5e' : currentRiskScore >= 65 ? '#f59e0b' : currentRiskScore >= 45 ? '#eab308' : '#10b981';

  // Circular HUD gauge
  const gaugeRadius = 44;
  const gaugeCircumference = 2 * Math.PI * gaugeRadius; // ~276.46
  const gaugeOffset = gaugeCircumference - (gaugeCircumference * Math.min(100, Math.max(0, currentRiskScore))) / 100;

  const radarData = activeOrg
    ? [
        { category: 'Authentication', risk: activeOrg.riskBreakdown.authentication, defense: Math.max(10, 100 - activeOrg.riskBreakdown.authentication) },
        { category: 'Data Security', risk: activeOrg.riskBreakdown.dataSecurity, defense: Math.max(10, 100 - activeOrg.riskBreakdown.dataSecurity) },
        { category: 'Network', risk: activeOrg.riskBreakdown.networkSecurity, defense: Math.max(10, 100 - activeOrg.riskBreakdown.networkSecurity) },
        { category: 'Endpoints', risk: activeOrg.riskBreakdown.endpointSecurity, defense: Math.max(10, 100 - activeOrg.riskBreakdown.endpointSecurity) },
        { category: 'Users / IAM', risk: activeOrg.riskBreakdown.userRisk, defense: Math.max(10, 100 - activeOrg.riskBreakdown.userRisk) }
      ]
    : [];

  const trendData = [
    { time: '04:00', score: 62 },
    { time: '06:00', score: 64 },
    { time: '08:00', score: 72 },
    { time: '09:00', score: 78 },
    { time: '09:30', score: 84 },
    { time: '09:44', score: currentRiskScore }
  ];

  if (isLoading || !activeOrg) {
    return (
      <div className="p-8 flex items-center justify-center text-slate-400 font-mono">
        <Activity className="w-6 h-6 animate-spin text-cyan-400 mr-2" />
        <span>Ingesting CyberGuard Grid SOC Telemetry...</span>
      </div>
    );
  }

  // Filter actions for current active organization only
  const orgResponseActions = responseActions.filter((a) => a.orgId === activeOrg.id);
  const displayActions = orgResponseActions.slice(0, 4);

  const categoryCards = [
    { title: 'Authentication', score: activeOrg.riskBreakdown.authentication, severity: 'Critical', bg: 'bg-rose-950/40 border-rose-800/80 text-rose-400', link: '/cyber-risk' },
    { title: 'Data Security', score: activeOrg.riskBreakdown.dataSecurity, severity: 'Critical', bg: 'bg-rose-950/40 border-rose-800/80 text-rose-400', link: '/privacy-engine' },
    { title: 'Network', score: activeOrg.riskBreakdown.networkSecurity, severity: 'High', bg: 'bg-amber-950/40 border-amber-800/80 text-amber-400', link: '/collaborative-network' },
    { title: 'Endpoints', score: activeOrg.riskBreakdown.endpointSecurity, severity: 'High', bg: 'bg-amber-950/40 border-amber-800/80 text-amber-400', link: '/threat-detection' },
    { title: 'Users', score: activeOrg.riskBreakdown.userRisk, severity: 'Medium', bg: 'bg-blue-950/40 border-blue-800/80 text-blue-400', link: '/incidents' }
  ];

  const handleTopActionClick = async (idx: number) => {
    const act = displayActions[idx];
    if (act && act.status !== 'Completed') {
      setExecutingIdx(idx);
      const res = await executeResponseAction(act.id, act.incidentId);
      setExecutingIdx(null);

      if (res?.riskReduction) {
        setTopRemediationMsg(
          `✓ Remediation Action Executed! Risk score reduced from ${res.riskReduction.previousScore} to ${res.riskReduction.newScore} (-${res.riskReduction.pointsReduced} pts).`
        );
      } else {
        setTopRemediationMsg(`✓ Remediation Action Executed! Risk score posture improved.`);
      }
    }
  };

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 sm:space-y-8 max-w-7xl mx-auto">
      {/* Top Header Card */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex flex-wrap items-center gap-2 sm:gap-3">
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-100 uppercase">OVERVIEW DASHBOARD</h1>
            <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-mono bg-cyan-950 text-cyan-400 border border-cyan-800">
              ● LIVE SOC FEED
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time Cyber Risk Quantification, Active Threat Vectors & Threat Intelligence Summary for{' '}
            <strong className="text-slate-200">{activeOrg.name}</strong> ({activeOrg.type}).
          </p>
        </div>

        <div className="flex items-center space-x-3 w-full sm:w-auto">
          <div className="px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-800 flex items-center space-x-2.5 flex-1 sm:flex-initial">
            <Building2 className="w-4 h-4 sm:w-5 sm:h-5 text-cyan-400 shrink-0" />
            <div className="min-w-0">
              <div className="text-[10px] font-mono text-slate-500 uppercase truncate">Organization</div>
              <div className="text-xs font-bold text-slate-200 truncate">{activeOrg.name}</div>
            </div>
          </div>

          <div className="px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-800 flex items-center space-x-2.5 flex-1 sm:flex-initial">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse shrink-0"></span>
            <div className="min-w-0">
              <div className="text-[10px] font-mono text-slate-500 uppercase truncate">System Status</div>
              <div className="text-xs font-bold text-emerald-400 truncate">● Operational</div>
            </div>
          </div>
        </div>
      </div>

      {/* Main Grid: Risk Score Card & Category Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Score Card with Circular HUD Gauge */}
        <div
          onClick={() => navigate('/cyber-risk')}
          className="glass-panel p-5 sm:p-6 rounded-2xl border border-rose-500/30 flex flex-col justify-between relative overflow-hidden bg-gradient-to-br from-rose-950/20 via-slate-900 to-slate-950 cursor-pointer hover:border-rose-500/80 transition-all group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider">CYBER RISK SCORE</span>
            <span
              className={`px-2.5 py-1 rounded text-xs font-mono font-bold border uppercase ${
                currentSeverity === 'CRITICAL'
                  ? 'bg-rose-950 text-rose-400 border-rose-800'
                  : currentSeverity === 'HIGH'
                  ? 'bg-amber-950 text-amber-400 border-amber-800'
                  : 'bg-emerald-950 text-emerald-400 border-emerald-800'
              }`}
            >
              {currentSeverity}
            </span>
          </div>

          {/* Circular HUD Gauge & Metrics */}
          <div className="my-3 flex items-center justify-between gap-4">
            <div className="relative flex items-center justify-center shrink-0">
              <svg width="108" height="108" className="transform -rotate-90">
                <circle
                  cx="54"
                  cy="54"
                  r={gaugeRadius}
                  stroke="#1e293b"
                  strokeWidth="8"
                  fill="transparent"
                />
                <circle
                  cx="54"
                  cy="54"
                  r={gaugeRadius}
                  stroke={scoreColor}
                  strokeWidth="8"
                  strokeDasharray={gaugeCircumference}
                  strokeDashoffset={gaugeOffset}
                  strokeLinecap="round"
                  fill="transparent"
                  className="transition-all duration-1000 ease-out"
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-2xl font-black font-mono tracking-tight" style={{ color: scoreColor }}>
                  {currentRiskScore}
                </span>
                <span className="text-[10px] font-mono text-slate-400 uppercase">/ 100</span>
              </div>
            </div>

            <div className="flex-1 space-y-1.5">
              <div className="text-xs font-mono text-slate-200 font-bold">Continuous Posture</div>
              <div className="text-[11px] text-slate-400 leading-tight">
                Quantified across CVE vectors, MITRE ATT&CK patterns, and boundary exposure.
              </div>
              <div className="text-[10px] font-mono text-cyan-400 flex items-center space-x-1">
                <span>Weighted LCS Formulation</span>
              </div>
            </div>
          </div>

          {/* Trend sparkline */}
          <div className="h-14 w-full -mb-2">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData}>
                <defs>
                  <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={scoreColor} stopOpacity={0.4} />
                    <stop offset="95%" stopColor={scoreColor} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <Area type="monotone" dataKey="score" stroke={scoreColor} strokeWidth={2} fillOpacity={1} fill="url(#riskGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
            <span className="flex items-center text-rose-400 group-hover:text-rose-300 font-medium">
              <TrendingUp className="w-3.5 h-3.5 mr-1 shrink-0" /> Click to evaluate weighted formula
            </span>
            <span className="font-mono text-[11px] text-slate-500 hidden sm:inline">Live Quantification</span>
          </div>
        </div>

        {/* Risk Categories */}
        <div className="lg:col-span-2 glass-panel p-5 sm:p-6 rounded-2xl border border-slate-800/80 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">RISK BY CATEGORY</h3>
            <span className="text-xs font-mono text-cyan-400">5 Categories Evaluated</span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
            {categoryCards.map((cat) => (
              <div
                key={cat.title}
                onClick={() => navigate(cat.link)}
                className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 hover:border-cyan-500/50 cursor-pointer flex flex-col justify-between space-y-3 transition-all"
              >
                <span className="text-[11px] font-medium text-slate-400">{cat.title}</span>
                <div className="flex items-baseline justify-between">
                  <span className="text-xl sm:text-2xl font-black font-mono text-slate-100">{cat.score}</span>
                  <span className={`text-[9px] sm:text-[10px] font-mono px-1.5 py-0.5 rounded border ${cat.bg}`}>
                    {cat.severity}
                  </span>
                </div>
                <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                  <div
                    className={`h-full ${cat.score >= 80 ? 'bg-rose-500' : cat.score >= 65 ? 'bg-amber-500' : 'bg-blue-500'}`}
                    style={{ width: `${cat.score}%` }}
                  ></div>
                </div>
              </div>
            ))}
          </div>

          {/* Active Threats Counter */}
          <div className="pt-2">
            <div className="text-xs font-mono text-slate-400 mb-2">ACTIVE THREAT BREAKDOWN</div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 sm:gap-3">
              <div
                onClick={() => navigate('/incidents')}
                className="p-3 rounded-lg bg-rose-950/40 border border-rose-800/60 text-center cursor-pointer hover:border-rose-500 transition-all"
              >
                <div className="text-xs font-mono text-rose-400">CRITICAL</div>
                <div className="text-xl font-bold font-mono text-rose-400">{activeOrg.activeThreatsCount.critical}</div>
              </div>
              <div
                onClick={() => navigate('/incidents')}
                className="p-3 rounded-lg bg-amber-950/40 border border-amber-800/60 text-center cursor-pointer hover:border-amber-500 transition-all"
              >
                <div className="text-xs font-mono text-amber-400">HIGH</div>
                <div className="text-xl font-bold font-mono text-amber-400">{activeOrg.activeThreatsCount.high}</div>
              </div>
              <div
                onClick={() => navigate('/incidents')}
                className="p-3 rounded-lg bg-blue-950/40 border border-blue-800/60 text-center cursor-pointer hover:border-blue-500 transition-all"
              >
                <div className="text-xs font-mono text-blue-400">MEDIUM</div>
                <div className="text-xl font-bold font-mono text-blue-400">{activeOrg.activeThreatsCount.medium}</div>
              </div>
              <div
                onClick={() => navigate('/incidents')}
                className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-center cursor-pointer hover:border-slate-700 transition-all"
              >
                <div className="text-xs font-mono text-slate-400">LOW</div>
                <div className="text-xl font-bold font-mono text-slate-300">{activeOrg.activeThreatsCount.low}</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Row 2: Multi-Vector Security Radar & Top Priority Remediation */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Security Posture Radar Card */}
        <div className="glass-panel p-6 rounded-2xl border border-cyan-500/30 space-y-4 flex flex-col justify-between">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center space-x-2">
              <ShieldCheck className="w-5 h-5 text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">SECURITY POSTURE RADAR</h3>
            </div>
            <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 text-xs font-mono font-bold border border-cyan-800">
              NIST CSF & MITRE
            </span>
          </div>

          <p className="text-xs text-slate-400">
            Multi-vector defense posture evaluation for <strong>{activeOrg.name}</strong>. Cyan indicates defensive resilience; Rose indicates residual risk exposure.
          </p>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={radarData}>
                <PolarGrid stroke="#334155" strokeDasharray="3 3" />
                <PolarAngleAxis dataKey="category" tick={{ fill: '#94a3b8', fontSize: 10, fontFamily: 'monospace' }} />
                <PolarRadiusAxis angle={30} domain={[0, 100]} stroke="#475569" tick={{ fill: '#64748b', fontSize: 9 }} />
                <Radar name="Defensive Resilience" dataKey="defense" stroke="#06b6d4" fill="#06b6d4" fillOpacity={0.35} strokeWidth={2} />
                <Radar name="Risk Exposure" dataKey="risk" stroke="#f43f5e" fill="#f43f5e" fillOpacity={0.2} strokeWidth={1.5} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '0.75rem', fontSize: '11px', fontFamily: 'monospace' }}
                  itemStyle={{ color: '#f8fafc' }}
                />
              </RadarChart>
            </ResponsiveContainer>
          </div>

          <div className="flex items-center justify-around pt-2 border-t border-slate-800/80 text-[11px] font-mono">
            <div className="flex items-center space-x-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-400"></span>
              <span className="text-slate-300">Resilience: {Math.max(0, Math.round(100 - currentRiskScore))}%</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500"></span>
              <span className="text-slate-300">Exposure: {currentRiskScore}%</span>
            </div>
            <button
              onClick={() => navigate('/cyber-risk')}
              className="text-cyan-400 hover:text-cyan-300 underline underline-offset-2 text-xs"
            >
              Analyze Factors →
            </button>
          </div>
        </div>

        {/* Top Priority Action Card */}
        <div className="glass-panel p-6 rounded-2xl border border-amber-500/30 space-y-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <AlertTriangle className="w-5 h-5 text-amber-400" />
                <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">TOP PRIORITY REMEDIATION</h3>
              </div>
              <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-400 text-xs font-mono font-bold border border-rose-800">
                Risk: {currentRiskScore} / 100
              </span>
            </div>

            <div className="mt-3">
              <h4 className="text-base font-bold text-slate-200">{activeOrg.name} — Threat Mitigation Playbook</h4>
              <p className="text-xs text-slate-400 mt-1">
                Active security exposure parameters detected for {activeOrg.name} ({activeOrg.type}). Click an action to execute remediation!
              </p>
            </div>
          </div>

          {/* Success Banner */}
          {topRemediationMsg && (
            <div className="p-3 rounded-xl bg-emerald-950/80 border border-emerald-500/80 text-emerald-300 text-xs font-mono font-bold flex items-center justify-between animate-fadeIn">
              <div className="flex items-center space-x-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>{topRemediationMsg}</span>
              </div>
              <button onClick={() => setTopRemediationMsg(null)} className="text-slate-400 hover:text-slate-200 text-[10px]">
                Dismiss
              </button>
            </div>
          )}

          <div className="space-y-2">
            <div className="text-xs font-mono text-slate-400 uppercase">RECOMMENDED ACTIONS FOR {activeOrg.name.toUpperCase()} (CLICK TO EXECUTE)</div>
            {displayActions.map((act, i) => {
              const isDone = act.status === 'Completed';
              return (
                <div
                  key={act.id}
                  onClick={() => !isDone && handleTopActionClick(i)}
                  className={`flex items-center justify-between p-3 rounded-lg border text-xs transition-all ${
                    isDone
                      ? 'bg-slate-950/60 border-emerald-900/60 opacity-85'
                      : 'bg-slate-900 hover:bg-slate-800 border-slate-800 hover:border-cyan-500/60 cursor-pointer'
                  }`}
                >
                  <div className="flex items-center space-x-2.5 flex-1 pr-2">
                    <Zap className={`w-4 h-4 shrink-0 ${isDone ? 'text-emerald-400' : 'text-cyan-400'}`} />
                    <span className={isDone ? 'text-slate-300 font-medium line-through' : 'text-slate-200 font-medium'}>
                      {act.title}
                    </span>
                  </div>

                  {isDone ? (
                    <span className="px-2.5 py-1 rounded bg-emerald-950 text-emerald-400 font-mono text-[10px] font-bold border border-emerald-800 flex items-center space-x-1 shrink-0">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>✓ Executed (-{act.estimatedRiskReduction} pts)</span>
                    </span>
                  ) : (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleTopActionClick(i);
                      }}
                      disabled={executingIdx === i}
                      className="px-3 py-1.5 rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-mono text-[11px] font-bold shadow glow-cyan shrink-0 flex items-center space-x-1 transition-all"
                    >
                      <Play className={`w-3 h-3 fill-slate-950 ${executingIdx === i ? 'animate-spin' : ''}`} />
                      <span>{executingIdx === i ? 'Executing...' : 'Execute'}</span>
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Row 3: Threat Mesh Intelligence & SOC Feed */}
      <div className="glass-panel p-6 rounded-2xl border border-cyan-500/30 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center space-x-2">
            <Share2 className="w-5 h-5 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">LIVE INTELLIGENCE & THREAT MESH</h3>
          </div>
          <button
            onClick={() => navigate('/threat-intelligence')}
            className="px-2.5 py-1 rounded-lg bg-cyan-950 text-cyan-400 text-xs font-mono font-bold border border-cyan-800 hover:bg-cyan-900 transition-colors flex items-center space-x-1"
          >
            <span>Vulnerability Hub →</span>
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div onClick={() => navigate('/threat-intelligence')} className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 text-center cursor-pointer hover:border-cyan-500 transition-all">
            <div className="text-[10px] font-mono text-slate-500 uppercase">Live Database CVEs</div>
            <div className="text-2xl font-black font-mono text-cyan-400 mt-1">
              {vulnerabilityStats?.total ?? 467}
            </div>
          </div>
          <div onClick={() => navigate('/threat-intelligence')} className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 text-center cursor-pointer hover:border-cyan-500 transition-all">
            <div className="text-[10px] font-mono text-slate-500 uppercase flex items-center justify-center space-x-1">
              <span>CISA KEV</span>
              <Flame className="w-3 h-3 text-amber-400" />
            </div>
            <div className="text-2xl font-black font-mono text-amber-400 mt-1">
              {vulnerabilityStats?.knownExploited ?? 150}
            </div>
          </div>
          <div onClick={() => navigate('/dlt-ledger')} className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 text-center cursor-pointer hover:border-cyan-500 transition-all">
            <div className="text-[10px] font-mono text-slate-500 uppercase">DLT Blocks</div>
            <div className="text-2xl font-black font-mono text-emerald-400 mt-1">
              3
            </div>
          </div>
        </div>

        <div className="space-y-2">
          <div className="text-xs font-mono text-slate-400 uppercase">RECENT SOC INTELLIGENCE LOG</div>
          {[
            { time: '09:44', text: `Live feed: Ingested ${vulnerabilityStats?.total || 467} normalized vulnerability records`, color: 'text-cyan-400', link: '/threat-intelligence' },
            { time: '09:42', text: `Suspicious activity telemetry logged for ${activeOrg.name}`, color: 'text-rose-400', link: '/threat-detection' },
            { time: '09:38', text: 'Threat pattern TH-7821 matched with 92% similarity', color: 'text-amber-400', link: '/collaborative-network' },
            { time: '09:31', text: `Cyber risk score updated dynamically (${currentRiskScore} RS)`, color: 'text-rose-400', link: '/cyber-risk' },
            { time: '09:20', text: 'Threat intelligence hash committed to DLT Ledger #10421', color: 'text-emerald-400', link: '/dlt-ledger' }
          ].map((log, idx) => (
            <div
              key={idx}
              onClick={() => navigate(log.link)}
              className="flex items-center justify-between p-2 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-cyan-500/50 cursor-pointer text-xs transition-all"
            >
              <span className="font-mono text-slate-500 text-[11px]">{log.time}</span>
              <span className={`truncate mx-3 ${log.color}`}>{log.text}</span>
              <ArrowUpRight className="w-3.5 h-3.5 text-slate-600 shrink-0" />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
