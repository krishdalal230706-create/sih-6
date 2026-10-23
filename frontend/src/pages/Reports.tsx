import React, { useState, useRef } from 'react';
import {
  FileText,
  Printer,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Activity,
  TrendingUp,
  TrendingDown,
  CheckCircle2,
  XCircle,
  Crosshair,
  Database,
  Network,
  Lock,
  Eye,
  Building2,
  Clock,
  Download,
  BarChart2,
  Zap,
  Radio,
  Star
} from 'lucide-react';
import {
  ResponsiveContainer,
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell
} from 'recharts';
import { useApp } from '../context/AppContext';

const SeverityBadge: React.FC<{ score: number }> = ({ score }) => {
  const s = score >= 80 ? 'CRITICAL' : score >= 65 ? 'HIGH' : score >= 45 ? 'MEDIUM' : 'LOW';
  const cls =
    s === 'CRITICAL' ? 'bg-rose-950 text-rose-400 border-rose-800' :
    s === 'HIGH'     ? 'bg-amber-950 text-amber-400 border-amber-800' :
    s === 'MEDIUM'   ? 'bg-blue-950 text-blue-400 border-blue-800' :
                       'bg-emerald-950 text-emerald-400 border-emerald-800';
  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${cls}`}>{s}</span>
  );
};

const RiskBar: React.FC<{ value: number; label: string }> = ({ value, label }) => {
  const color = value >= 80 ? '#f43f5e' : value >= 65 ? '#f59e0b' : value >= 45 ? '#3b82f6' : '#10b981';
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-[11px] font-mono">
        <span className="text-slate-400">{label}</span>
        <span style={{ color }} className="font-bold">{value}/100</span>
      </div>
      <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{ width: `${value}%`, backgroundColor: color }}
        />
      </div>
    </div>
  );
};

export const Reports: React.FC = () => {
  const { activeOrg, riskData, incidents, responseActions, threatPatterns, ledgerRecords, attackScenarios, organizations } = useApp();
  const [isGenerated, setIsGenerated] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const reportRef = useRef<HTMLDivElement>(null);

  const now = new Date();
  const dateStr = now.toLocaleDateString('en-IN', { day: '2-digit', month: 'long', year: 'numeric' });
  const timeStr = now.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' });

  const handleGenerateReport = async () => {
    setIsGenerating(true);
    await new Promise((r) => setTimeout(r, 1200));
    setIsGenerated(true);
    setIsGenerating(false);
  };

  const handlePrint = () => window.print();

  // Computed data
  const orgIncidents = incidents.filter((i) => i.orgId === activeOrg?.id);
  const orgActions   = responseActions.filter((a) => a.orgId === activeOrg?.id);
  const completedActions = orgActions.filter((a) => a.status === 'Completed');
  const pendingActions   = orgActions.filter((a) => a.status === 'Pending');
  const totalRiskReduced = completedActions.reduce((s, a) => s + a.estimatedRiskReduction, 0);
  const activeIncidents  = orgIncidents.filter((i) => i.status !== 'Resolved');

  const riskScore  = riskData?.overallRiskScore ?? activeOrg?.riskScore ?? 84;
  const severity   = riskData?.severity ?? (riskScore >= 80 ? 'CRITICAL' : riskScore >= 65 ? 'HIGH' : 'MEDIUM');

  // Radar data for risk breakdown
  const radarData = activeOrg ? [
    { subject: 'Auth',     score: activeOrg.riskBreakdown.authentication },
    { subject: 'Network',  score: activeOrg.riskBreakdown.networkSecurity },
    { subject: 'Data',     score: activeOrg.riskBreakdown.dataSecurity },
    { subject: 'Endpoint', score: activeOrg.riskBreakdown.endpointSecurity },
    { subject: 'Users',    score: activeOrg.riskBreakdown.userRisk },
  ] : [];

  // Bar chart: orgs risk comparison
  const orgBarData = Object.values(
    organizations.reduce((acc: any, o) => { acc[o.id] = o; return acc; }, {})
  ).map((o: any) => ({ name: o.name.split(' ')[0], score: o.riskScore }));

  const topScenario = attackScenarios.sort((a, b) => b.scenarioRisk - a.scenarioRisk)[0];

  const scoreColor = riskScore >= 80 ? '#f43f5e' : riskScore >= 65 ? '#f59e0b' : '#10b981';

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 max-w-7xl mx-auto">
      {/* ── Page Header ── */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-100 uppercase">Security Reports</h1>
          <p className="text-xs text-slate-400 mt-1">
            Generate executive-grade cyber risk audit reports with live data, risk breakdowns, and remediation status.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2 sm:gap-3 w-full sm:w-auto">
          <button
            onClick={handleGenerateReport}
            disabled={isGenerating}
            className="flex-1 sm:flex-initial flex items-center justify-center space-x-2 px-4 sm:px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs glow-cyan transition-all shadow-lg disabled:opacity-60"
          >
            {isGenerating ? (
              <Activity className="w-4 h-4 animate-spin" />
            ) : (
              <FileText className="w-4 h-4" />
            )}
            <span>{isGenerating ? 'Generating...' : 'Generate Security Report'}</span>
          </button>
          {isGenerated && (
            <button
              onClick={handlePrint}
              className="flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-slate-900 border border-slate-700 hover:border-slate-600 text-slate-200 text-xs font-bold transition-all"
            >
              <Printer className="w-4 h-4" />
              <span>Print / Export PDF</span>
            </button>
          )}
        </div>
      </div>

      {/* ── Report Type Cards ── */}
      {!isGenerated && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {[
            { icon: ShieldAlert, title: 'Executive Risk Report', desc: 'Complete cyber risk posture, breakdown scores, and critical vulnerabilities for executive review.', color: 'text-rose-400', border: 'border-rose-800/50' },
            { icon: Crosshair,   title: 'Attack Simulation Summary', desc: 'Simulated adversary progression, exploited weak points, and recommended mitigations.', color: 'text-amber-400', border: 'border-amber-800/50' },
            { icon: Database,    title: 'DLT Trust Audit Report', desc: 'Immutable threat pattern ledger records, block integrity verification, and validator consensus.', color: 'text-cyan-400', border: 'border-cyan-800/50' },
          ].map((r) => (
            <div key={r.title} className={`glass-panel p-6 rounded-2xl border ${r.border} space-y-3 cursor-pointer hover:scale-[1.01] transition-transform`} onClick={handleGenerateReport}>
              <r.icon className={`w-8 h-8 ${r.color}`} />
              <h3 className={`text-sm font-bold ${r.color}`}>{r.title}</h3>
              <p className="text-xs text-slate-400 leading-relaxed">{r.desc}</p>
              <div className={`text-[10px] font-mono ${r.color} flex items-center space-x-1`}>
                <Star className="w-3 h-3" />
                <span>Click to generate →</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════
          GENERATED REPORT
      ══════════════════════════════════════════════════════════ */}
      {isGenerated && activeOrg && (
        <div ref={reportRef} className="space-y-6 print:space-y-4">

          {/* ── Report Cover ── */}
          <div className="glass-panel rounded-2xl border border-cyan-500/30 overflow-hidden">
            {/* Top accent bar */}
            <div className="h-2 bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600" />

            <div className="p-8">
              <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
                {/* Left: Branding + Title */}
                <div className="space-y-3">
                  <div className="flex items-center space-x-3">
                    <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
                      <ShieldCheck className="w-6 h-6 text-slate-950" />
                    </div>
                    <div>
                      <div className="text-[10px] font-mono text-cyan-400 uppercase tracking-widest">CyberGuard Grid</div>
                      <div className="text-xs font-mono text-slate-400">SOC COMMAND CENTER</div>
                    </div>
                  </div>
                  <div>
                    <h2 className="text-2xl font-black text-slate-100 uppercase tracking-tight">
                      Executive Security Audit Report
                    </h2>
                    <p className="text-sm text-cyan-400 font-mono mt-0.5">Comprehensive Cyber Risk & Threat Intelligence Assessment</p>
                  </div>
                </div>

                {/* Right: Score Gauge */}
                <div className="flex flex-col items-center p-6 rounded-2xl bg-slate-950/60 border border-slate-800 min-w-[160px]">
                  <div className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-2">Overall Risk Score</div>
                  <div className="text-5xl font-black font-mono" style={{ color: scoreColor }}>{riskScore}</div>
                  <div className="text-lg font-mono text-slate-400 mt-0.5">/100</div>
                  <div className={`mt-3 px-3 py-1 rounded-lg text-xs font-mono font-bold border ${
                    severity === 'CRITICAL' ? 'bg-rose-950 text-rose-400 border-rose-800' :
                    severity === 'HIGH'     ? 'bg-amber-950 text-amber-400 border-amber-800' :
                                             'bg-emerald-950 text-emerald-400 border-emerald-800'
                  }`}>
                    {severity}
                  </div>
                </div>
              </div>

              {/* Report Meta */}
              <div className="mt-6 pt-4 border-t border-slate-800 grid grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono">
                {[
                  { label: 'Organization', value: activeOrg.name },
                  { label: 'Sector',       value: activeOrg.type },
                  { label: 'Report Date',  value: dateStr },
                  { label: 'Generated At', value: timeStr },
                ].map((m) => (
                  <div key={m.label}>
                    <div className="text-slate-500 uppercase text-[10px] tracking-wider">{m.label}</div>
                    <div className="text-slate-200 font-semibold mt-0.5">{m.value}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* ── Section 1: Executive Summary KPIs ── */}
          <section className="space-y-3">
            <div className="flex items-center space-x-2 pb-1 border-b border-slate-800">
              <BarChart2 className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">1. Executive Summary</h3>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { label: 'Risk Score',         value: `${riskScore}/100`,      sub: severity,        color: 'text-rose-400',    icon: ShieldAlert },
                { label: 'Active Incidents',    value: activeIncidents.length,  sub: 'Unresolved',    color: 'text-amber-400',   icon: AlertTriangle },
                { label: 'Pending Remediations',value: pendingActions.length,   sub: 'Actions queued',color: 'text-cyan-400',    icon: Zap },
                { label: 'Risk Points Reduced', value: `-${totalRiskReduced}`,  sub: 'pts via actions',color: 'text-emerald-400', icon: TrendingDown },
              ].map((k) => (
                <div key={k.label} className="glass-panel p-5 rounded-xl border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">{k.label}</span>
                    <k.icon className={`w-4 h-4 ${k.color}`} />
                  </div>
                  <div className={`text-2xl font-black font-mono ${k.color}`}>{k.value}</div>
                  <div className="text-[10px] font-mono text-slate-500">{k.sub}</div>
                </div>
              ))}
            </div>
          </section>

          {/* ── Section 2: Risk Breakdown ── */}
          <section className="space-y-3">
            <div className="flex items-center space-x-2 pb-1 border-b border-slate-800">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">2. Risk Category Breakdown</h3>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Bar breakdown */}
              <div className="glass-panel p-6 rounded-xl border border-slate-800 space-y-4">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Category Risk Scores</h4>
                <div className="space-y-3">
                  <RiskBar label="Authentication"    value={activeOrg.riskBreakdown.authentication} />
                  <RiskBar label="Data Security"     value={activeOrg.riskBreakdown.dataSecurity} />
                  <RiskBar label="Network Security"  value={activeOrg.riskBreakdown.networkSecurity} />
                  <RiskBar label="Endpoint Security" value={activeOrg.riskBreakdown.endpointSecurity} />
                  <RiskBar label="User Risk"         value={activeOrg.riskBreakdown.userRisk} />
                </div>
              </div>

              {/* Radar chart */}
              <div className="glass-panel p-6 rounded-xl border border-slate-800 space-y-3">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Risk Vector Radar</h4>
                <ResponsiveContainer width="100%" height={220}>
                  <RadarChart data={radarData} cx="50%" cy="50%" outerRadius="70%">
                    <PolarGrid stroke="#1e293b" />
                    <PolarAngleAxis dataKey="subject" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                    <Radar name="Risk" dataKey="score" stroke="#06b6d4" fill="#06b6d4" fillOpacity={0.25} strokeWidth={2} />
                  </RadarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </section>

          {/* ── Section 3: Organization Profile ── */}
          <section className="space-y-3">
            <div className="flex items-center space-x-2 pb-1 border-b border-slate-800">
              <Building2 className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">3. Organization Security Profile</h3>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
              {[
                { label: 'Users',              value: activeOrg.usersCount.toLocaleString() },
                { label: 'Critical Systems',   value: activeOrg.criticalSystems },
                { label: 'Internet-Facing',    value: activeOrg.internetFacingServices },
                { label: 'Known CVEs',         value: activeOrg.knownVulnerabilities },
                { label: 'Data Sensitivity',   value: activeOrg.dataSensitivity },
                { label: 'Past Incidents',     value: activeOrg.previousIncidents },
              ].map((s) => (
                <div key={s.label} className="glass-panel p-4 rounded-xl border border-slate-800 text-center">
                  <div className="text-[10px] font-mono text-slate-500 uppercase">{s.label}</div>
                  <div className="text-lg font-black font-mono text-slate-200 mt-1">{s.value}</div>
                </div>
              ))}
            </div>

            <div className="glass-panel p-5 rounded-xl border border-slate-800 grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">Authentication Methods</div>
                <div className="flex flex-wrap gap-2">
                  {activeOrg.authenticationMethods.map((m) => (
                    <span key={m} className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-900 border border-slate-700 text-slate-300">{m}</span>
                  ))}
                </div>
              </div>
              <div className="space-y-2">
                <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">Deployed Security Controls</div>
                <div className="flex flex-wrap gap-2">
                  {activeOrg.securityControls.map((c) => (
                    <span key={c} className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950/50 border border-emerald-800/50 text-emerald-400">{c}</span>
                  ))}
                </div>
              </div>
            </div>
          </section>

          {/* ── Section 4: Active Incidents ── */}
          <section className="space-y-3">
            <div className="flex items-center space-x-2 pb-1 border-b border-slate-800">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">4. Active Incident Register</h3>
            </div>
            {orgIncidents.length === 0 ? (
              <div className="glass-panel p-8 rounded-xl border border-emerald-800/50 text-center space-y-2">
                <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
                <p className="text-emerald-400 font-mono font-bold text-sm">No incidents logged for this organization.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {orgIncidents.map((inc) => (
                  <div key={inc.id} className="glass-panel p-5 rounded-xl border border-slate-800">
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                      <div className="space-y-1 flex-1">
                        <div className="flex items-center space-x-3 flex-wrap gap-2">
                          <span className="text-xs font-mono font-bold text-cyan-400">{inc.incidentId}</span>
                          <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-bold ${
                            inc.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-400 border-rose-800' : 'bg-amber-950 text-amber-400 border-amber-800'
                          }`}>{inc.severity}</span>
                          <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                            inc.status === 'Resolved' ? 'bg-emerald-950 text-emerald-400 border-emerald-800' :
                            inc.status === 'Contained' ? 'bg-blue-950 text-blue-400 border-blue-800' :
                            'bg-rose-950 text-rose-400 border-rose-800'
                          }`}>{inc.status}</span>
                        </div>
                        <h4 className="text-sm font-bold text-slate-100">{inc.title}</h4>
                        <p className="text-xs text-slate-400 leading-relaxed">{inc.description}</p>
                      </div>
                      <div className="text-right shrink-0 space-y-1">
                        <div className="text-[10px] font-mono text-slate-500">Detected</div>
                        <div className="text-xs font-mono text-slate-300">{inc.detectionTime}</div>
                        <div className="text-[10px] font-mono text-slate-500">Confidence</div>
                        <div className="text-xs font-bold font-mono text-amber-400">{inc.confidence}%</div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* ── Section 5: Remediation Status ── */}
          <section className="space-y-3">
            <div className="flex items-center space-x-2 pb-1 border-b border-slate-800">
              <Zap className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">5. Remediation Playbook Status</h3>
            </div>
            <div className="grid grid-cols-3 gap-2 sm:gap-4 mb-3">
              {[
                { label: 'Total Actions',  value: orgActions.length,        color: 'text-cyan-400' },
                { label: 'Completed',      value: completedActions.length,   color: 'text-emerald-400' },
                { label: 'Pending',        value: pendingActions.length,     color: 'text-amber-400' },
              ].map((s) => (
                <div key={s.label} className="glass-panel p-2.5 sm:p-4 rounded-xl border border-slate-800 text-center min-w-0">
                  <div className="text-[10px] font-mono text-slate-500 uppercase truncate">{s.label}</div>
                  <div className={`text-lg sm:text-2xl font-black font-mono ${s.color} mt-1 truncate`}>{s.value}</div>
                </div>
              ))}
            </div>
            <div className="space-y-2">
              {orgActions.map((act) => (
                <div key={act.id} className={`flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-4 rounded-xl border text-xs ${
                  act.status === 'Completed' ? 'bg-emerald-950/20 border-emerald-900/60' : 'glass-panel border-slate-800'
                }`}>
                  <div className="flex items-center space-x-3 flex-1 min-w-0">
                    {act.status === 'Completed' ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    ) : (
                      <XCircle className="w-4 h-4 text-slate-600 shrink-0" />
                    )}
                    <div className="min-w-0">
                      <div className="font-bold text-slate-200 truncate">{act.title}</div>
                      <div className="text-[10px] text-slate-500 font-mono line-clamp-1">{act.reason}</div>
                    </div>
                  </div>
                  <div className="flex flex-wrap items-center gap-2 sm:gap-3 shrink-0 sm:ml-4">
                    <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                      act.priority === 'CRITICAL' ? 'bg-rose-950 text-rose-400 border-rose-800' : 'bg-amber-950 text-amber-400 border-amber-800'
                    }`}>{act.priority}</span>
                    <span className="text-emerald-400 font-mono font-bold">-{act.estimatedRiskReduction} pts</span>
                    <span className={`font-mono font-bold ${act.status === 'Completed' ? 'text-emerald-400' : 'text-slate-500'}`}>{act.status}</span>
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* ── Section 6: Top Attack Scenario ── */}
          {topScenario && (
            <section className="space-y-3">
              <div className="flex items-center space-x-2 pb-1 border-b border-slate-800">
                <Crosshair className="w-4 h-4 text-rose-400" />
                <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">6. Highest-Risk Attack Scenario</h3>
              </div>
              <div className="glass-panel p-6 rounded-xl border border-rose-800/50 space-y-4">
                <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
                  <div className="space-y-1 flex-1">
                    <div className="flex items-center space-x-3">
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950 text-rose-400 border border-rose-800 font-bold">
                        Scenario Risk: {topScenario.scenarioRisk}/100
                      </span>
                      <span className="text-[10px] font-mono text-slate-400">Probability: {topScenario.probability}%</span>
                    </div>
                    <h4 className="text-base font-bold text-slate-100">{topScenario.name}</h4>
                    <p className="text-xs text-slate-400 leading-relaxed">{topScenario.description}</p>
                  </div>
                </div>
                <div className="space-y-1">
                  <div className="text-[10px] font-mono text-rose-400 uppercase font-bold">Critical Weak Point</div>
                  <div className="text-sm font-bold text-slate-200">{topScenario.criticalWeakPoint}</div>
                  <p className="text-xs text-slate-400">{topScenario.explanation}</p>
                </div>
                <div className="space-y-2">
                  <div className="text-[10px] font-mono text-slate-500 uppercase">Attack Progression Stages</div>
                  <div className="flex flex-wrap gap-2">
                    {topScenario.nodes.map((n, i) => (
                      <div key={n.id} className="flex items-center space-x-1 text-[10px] font-mono">
                        <span className="w-4 h-4 rounded-full bg-rose-900 text-rose-300 flex items-center justify-center text-[9px] font-bold">{i+1}</span>
                        <span className="text-slate-300">{n.stage}</span>
                        {i < topScenario.nodes.length - 1 && <span className="text-slate-700">→</span>}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </section>
          )}

          {/* ── Section 7: Threat Intelligence & DLT ── */}
          <section className="space-y-3">
            <div className="flex items-center space-x-2 pb-1 border-b border-slate-800">
              <Database className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">7. Threat Intelligence & DLT Trust Ledger</h3>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Threat Patterns */}
              <div className="glass-panel p-5 rounded-xl border border-slate-800 space-y-3">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
                  <Radio className="w-3.5 h-3.5 text-rose-400" />
                  <span>Shared Threat Patterns ({threatPatterns.length})</span>
                </h4>
                <div className="space-y-2">
                  {threatPatterns.map((tp) => (
                    <div key={tp.id} className="flex items-center justify-between p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs">
                      <div className="space-y-0.5">
                        <div className="font-mono font-bold text-cyan-400">{tp.patternCode}</div>
                        <div className="text-slate-400 text-[10px]">Origin: {tp.originOrgName}</div>
                      </div>
                      <div className="text-right space-y-0.5">
                        <SeverityBadge score={tp.severity === 'CRITICAL' ? 90 : tp.severity === 'HIGH' ? 70 : 50} />
                        <div className="text-[10px] font-mono text-slate-500">Confidence: {tp.confidence}%</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* DLT Ledger */}
              <div className="glass-panel p-5 rounded-xl border border-slate-800 space-y-3">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
                  <Lock className="w-3.5 h-3.5 text-emerald-400" />
                  <span>DLT Ledger Records ({ledgerRecords.length} blocks)</span>
                </h4>
                <div className="space-y-2">
                  {ledgerRecords.map((lr) => (
                    <div key={lr.blockNumber} className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-cyan-400 font-bold">Block #{lr.blockNumber}</span>
                        <span className="text-emerald-400 text-[10px] flex items-center space-x-1">
                          <CheckCircle2 className="w-3 h-3" />
                          <span>{lr.status}</span>
                        </span>
                      </div>
                      <div className="text-slate-400 text-[10px]">Threat: {lr.threatId} · Reporter: {lr.reporterOrg}</div>
                      <div className="text-slate-600 text-[9px] truncate">Hash: {lr.blockHash}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </section>

          {/* ── Section 8: Peer Organization Comparison ── */}
          <section className="space-y-3">
            <div className="flex items-center space-x-2 pb-1 border-b border-slate-800">
              <Network className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">8. Peer Organization Risk Comparison</h3>
            </div>
            <div className="glass-panel p-6 rounded-xl border border-slate-800">
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={orgBarData} margin={{ top: 5, right: 10, bottom: 5, left: -20 }}>
                  <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis domain={[0, 100]} tick={{ fill: '#475569', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <Tooltip
                    contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', fontSize: 11 }}
                    labelStyle={{ color: '#94a3b8' }}
                    itemStyle={{ color: '#e2e8f0' }}
                  />
                  <Bar dataKey="score" radius={[4, 4, 0, 0]}>
                    {orgBarData.map((entry: any, i) => (
                      <Cell
                        key={i}
                        fill={entry.score >= 80 ? '#f43f5e' : entry.score >= 65 ? '#f59e0b' : '#10b981'}
                        opacity={entry.name === activeOrg.name.split(' ')[0] ? 1 : 0.6}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
              <div className="flex items-center justify-center space-x-4 text-[10px] font-mono text-slate-500 mt-2">
                <span className="flex items-center space-x-1"><span className="w-3 h-2 rounded-sm bg-rose-500 inline-block" /> CRITICAL (≥80)</span>
                <span className="flex items-center space-x-1"><span className="w-3 h-2 rounded-sm bg-amber-500 inline-block" /> HIGH (65–79)</span>
                <span className="flex items-center space-x-1"><span className="w-3 h-2 rounded-sm bg-emerald-500 inline-block" /> MEDIUM/LOW (&lt;65)</span>
              </div>
            </div>
          </section>

          {/* ── Section 9: Recommendations ── */}
          <section className="space-y-3">
            <div className="flex items-center space-x-2 pb-1 border-b border-slate-800">
              <Star className="w-4 h-4 text-amber-400" />
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">9. Top Recommendations</h3>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {[
                { pri: '1', title: 'Enforce FIDO2 / WebAuthn Hardware MFA', desc: 'Replace SMS OTP and password-only flows with hardware-backed authentication across all critical systems to eliminate credential theft vectors.', color: 'border-rose-800/60 bg-rose-950/20', badge: 'CRITICAL' },
                { pri: '2', title: 'Deploy Zero Trust Microsegmentation', desc: 'Implement network microsegmentation to prevent lateral movement between identity providers, databases, and application servers.', color: 'border-rose-800/60 bg-rose-950/20', badge: 'CRITICAL' },
                { pri: '3', title: 'Enable UEBA & Behavioral Anomaly Detection', desc: 'Deploy User and Entity Behavior Analytics to flag unusual access patterns, off-hours queries, and privilege escalation in real-time.', color: 'border-amber-800/60 bg-amber-950/20', badge: 'HIGH' },
                { pri: '4', title: 'Patch All Known Vulnerabilities (CVEs)', desc: `Address all ${activeOrg.knownVulnerabilities} known CVEs within 30 days. Prioritize internet-facing services and RCE-capable vulnerabilities.`, color: 'border-amber-800/60 bg-amber-950/20', badge: 'HIGH' },
                { pri: '5', title: 'Implement Data Loss Prevention (DLP)', desc: 'Deploy DLP policies to detect and block bulk data exfiltration via outbound encrypted HTTPS channels and cloud storage endpoints.', color: 'border-blue-800/60 bg-blue-950/20', badge: 'MEDIUM' },
                { pri: '6', title: 'Join Collaborative Threat Network', desc: 'Share anonymized threat patterns with the CyberGuard Grid mesh network to benefit from early-warning intelligence from peer organizations.', color: 'border-cyan-800/60 bg-cyan-950/20', badge: 'MEDIUM' },
              ].map((r) => (
                <div key={r.pri} className={`p-5 rounded-xl border ${r.color} space-y-2`}>
                  <div className="flex items-center space-x-3">
                    <div className="w-6 h-6 rounded-full bg-slate-800 text-slate-200 font-bold font-mono text-xs flex items-center justify-center shrink-0">{r.pri}</div>
                    <div className="flex items-center space-x-2">
                      <span className="text-sm font-bold text-slate-100">{r.title}</span>
                      <SeverityBadge score={r.badge === 'CRITICAL' ? 90 : r.badge === 'HIGH' ? 70 : 50} />
                    </div>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed ml-9">{r.desc}</p>
                </div>
              ))}
            </div>
          </section>

          {/* ── Report Footer ── */}
          <div className="glass-panel p-5 rounded-xl border border-slate-800 flex flex-col md:flex-row items-center justify-between gap-3 text-[11px] font-mono text-slate-500">
            <div className="flex items-center space-x-3">
              <ShieldCheck className="w-5 h-5 text-cyan-400" />
              <span>CyberGuard Grid — AI-Powered Cyber Risk Quantification & Defense Platform</span>
            </div>
            <div className="flex items-center space-x-4">
              <span>Report ID: CGG-{now.getFullYear()}-{String(now.getMonth()+1).padStart(2,'0')}{String(now.getDate()).padStart(2,'0')}-{activeOrg.id.toUpperCase()}</span>
              <span className="text-emerald-400 flex items-center space-x-1">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>DLT Integrity Verified</span>
              </span>
            </div>
          </div>

        </div>
      )}

      {/* Print styles */}
      <style>{`
        @media print {
          .glass-panel { background: #fff !important; color: #000 !important; border-color: #ccc !important; }
          body { background: #fff !important; color: #000 !important; }
          header, aside, .fixed { display: none !important; }
        }
      `}</style>
    </div>
  );
};
