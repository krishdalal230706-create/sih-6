import React, { useState } from 'react';
import {
  ShieldAlert,
  Sliders,
  RefreshCw,
  PlusCircle,
  HelpCircle,
  AlertTriangle,
  TrendingUp,
  CheckCircle2,
  Lock,
  Layers,
  Building2,
  ShieldCheck,
  Plus,
  Trash2,
  BarChart3,
  ArrowUpRight
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell
} from 'recharts';
import { useApp } from '../context/AppContext';

export const CyberRisk: React.FC = () => {
  const { activeOrg, riskData, updateOrgProfile, addNotification } = useApp();

  const [formData, setFormData] = useState({
    usersCount: activeOrg?.usersCount || 14200,
    criticalSystems: activeOrg?.criticalSystems || 48,
    internetFacingServices: activeOrg?.internetFacingServices || 18,
    knownVulnerabilities: activeOrg?.knownVulnerabilities || 14,
    dataSensitivity: activeOrg?.dataSensitivity || 'CRITICAL'
  });

  const [weights, setWeights] = useState({
    auth: 25,
    network: 20,
    data: 20,
    vuln: 20,
    ctrl: 10,
    incident: 5
  });

  const [controls, setControls] = useState<string[]>(activeOrg?.securityControls || ['Firewall', 'Endpoint Antivirus', 'Basic SIEM']);
  const [newControl, setNewControl] = useState<string>('');
  const [isUpdating, setIsUpdating] = useState(false);

  // Sync form when active org changes
  React.useEffect(() => {
    if (activeOrg) {
      setFormData({
        usersCount: activeOrg.usersCount,
        criticalSystems: activeOrg.criticalSystems,
        internetFacingServices: activeOrg.internetFacingServices,
        knownVulnerabilities: activeOrg.knownVulnerabilities,
        dataSensitivity: activeOrg.dataSensitivity
      });
      setControls(activeOrg.securityControls || []);
    }
  }, [activeOrg?.id]);

  if (!activeOrg || !riskData) {
    return (
      <div className="p-8 space-y-6 max-w-7xl mx-auto flex flex-col items-center justify-center min-h-[60vh]">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
        <p className="font-mono text-xs text-slate-400">Loading Cyber Risk Quantification Engine...</p>
      </div>
    );
  }

  const handleSave = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setIsUpdating(true);
    await updateOrgProfile(activeOrg.id, { ...formData, securityControls: controls });
    setIsUpdating(false);
  };

  const handleAddControl = async () => {
    if (!newControl.trim()) return;
    const updated = [...controls, newControl.trim()];
    setControls(updated);
    setNewControl('');
    setIsUpdating(true);
    await updateOrgProfile(activeOrg.id, { ...formData, securityControls: updated });
    setIsUpdating(false);
    addNotification('Security Control Deployed', `Added security control: "${newControl.trim()}". Posture improved!`, 'SUCCESS', '/cyber-risk');
  };

  const handleRemoveControl = async (index: number) => {
    const updated = controls.filter((_, i) => i !== index);
    setControls(updated);
    setIsUpdating(true);
    await updateOrgProfile(activeOrg.id, { ...formData, securityControls: updated });
    setIsUpdating(false);
  };

  // Dynamic calculated score with current custom weights
  const customCalculatedScore = Math.round(
    activeOrg.riskBreakdown.authentication * (weights.auth / 100) +
    activeOrg.riskBreakdown.networkSecurity * (weights.network / 100) +
    activeOrg.riskBreakdown.dataSecurity * (weights.data / 100) +
    Math.min(100, formData.knownVulnerabilities * 4.5) * (weights.vuln / 100) +
    Math.max(0, 100 - controls.length * 15) * (weights.ctrl / 100) +
    50 * (weights.incident / 100)
  );

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 sm:space-y-8 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-100 uppercase">CYBER RISK QUANTIFICATION</h1>
          <p className="text-xs text-slate-400 mt-1">
            Transparent weighted formula model quantifying posture exposure, active exploitability, and risk contributors for {activeOrg.name}.
          </p>
        </div>

        <button
          onClick={() => handleSave()}
          disabled={isUpdating}
          className="w-full sm:w-auto flex items-center justify-center space-x-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition-all glow-cyan"
        >
          <RefreshCw className={`w-4 h-4 shrink-0 ${isUpdating ? 'animate-spin' : ''}`} />
          <span>RECALCULATE RISK SCORE</span>
        </button>
      </div>

      {/* Top Cards: Score & Transparent Formula */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Score Summary Card */}
        <div className="glass-panel p-5 sm:p-6 rounded-2xl border border-rose-500/40 bg-gradient-to-br from-rose-950/30 via-slate-900 to-slate-950 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold text-slate-400 uppercase">OVERALL RISK SCORE</span>
            <span className="px-2.5 py-1 rounded bg-rose-950 text-rose-400 text-xs font-mono font-bold border border-rose-800">
              {customCalculatedScore >= 80 ? 'CRITICAL' : customCalculatedScore >= 65 ? 'HIGH' : 'MEDIUM'}
            </span>
          </div>

          <div className="my-6">
            <div className="text-5xl sm:text-6xl font-black text-rose-500 font-mono tracking-tight">
              {customCalculatedScore} <span className="text-xl sm:text-2xl text-slate-500 font-normal">/ 100</span>
            </div>
            <div className="flex items-center space-x-2 mt-2 text-xs font-mono text-rose-400">
              <TrendingUp className="w-4 h-4 shrink-0" />
              <span>Weighted Formula Engine Active</span>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 text-[11px] font-mono text-slate-400 leading-relaxed">
            Formula normalization engine evaluates security controls against active threats and vulnerability parameters.
          </div>
        </div>

        {/* Transparent Formula Breakdown & Live Weight Sliders */}
        <div className="lg:col-span-2 glass-panel p-5 sm:p-6 rounded-2xl border border-slate-800 space-y-4">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
            <h3 className="text-xs sm:text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
              <Sliders className="w-4 h-4 text-cyan-400 shrink-0" />
              <span>TRANSPARENT WEIGHTED RISK FORMULA SLIDERS</span>
            </h3>
            <span className="text-xs font-mono text-cyan-400">Adjust Weights Live</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 sm:gap-4">
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
              <div className="flex justify-between text-[10px] font-mono text-slate-400">
                <span>Authentication</span>
                <span className="text-rose-400 font-bold">{weights.auth}%</span>
              </div>
              <input
                type="range"
                min="10"
                max="40"
                value={weights.auth}
                onChange={(e) => setWeights({ ...weights, auth: Number(e.target.value) })}
                className="w-full h-1.5 bg-slate-800 rounded appearance-none cursor-pointer accent-rose-500"
              />
              <div className="text-[11px] font-mono text-slate-300">Score: {activeOrg.riskBreakdown.authentication}</div>
            </div>

            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
              <div className="flex justify-between text-[10px] font-mono text-slate-400">
                <span>Network</span>
                <span className="text-amber-400 font-bold">{weights.network}%</span>
              </div>
              <input
                type="range"
                min="10"
                max="35"
                value={weights.network}
                onChange={(e) => setWeights({ ...weights, network: Number(e.target.value) })}
                className="w-full h-1.5 bg-slate-800 rounded appearance-none cursor-pointer accent-amber-500"
              />
              <div className="text-[11px] font-mono text-slate-300">Score: {activeOrg.riskBreakdown.networkSecurity}</div>
            </div>

            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
              <div className="flex justify-between text-[10px] font-mono text-slate-400">
                <span>Data Sensitivity</span>
                <span className="text-rose-400 font-bold">{weights.data}%</span>
              </div>
              <input
                type="range"
                min="10"
                max="35"
                value={weights.data}
                onChange={(e) => setWeights({ ...weights, data: Number(e.target.value) })}
                className="w-full h-1.5 bg-slate-800 rounded appearance-none cursor-pointer accent-rose-500"
              />
              <div className="text-[11px] font-mono text-slate-300">Score: {activeOrg.riskBreakdown.dataSecurity}</div>
            </div>

            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
              <div className="flex justify-between text-[10px] font-mono text-slate-400">
                <span>Vulnerabilities</span>
                <span className="text-amber-400 font-bold">{weights.vuln}%</span>
              </div>
              <input
                type="range"
                min="10"
                max="35"
                value={weights.vuln}
                onChange={(e) => setWeights({ ...weights, vuln: Number(e.target.value) })}
                className="w-full h-1.5 bg-slate-800 rounded appearance-none cursor-pointer accent-amber-500"
              />
              <div className="text-[11px] font-mono text-slate-300">Count: {formData.knownVulnerabilities}</div>
            </div>

            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
              <div className="flex justify-between text-[10px] font-mono text-slate-400">
                <span>Controls</span>
                <span className="text-emerald-400 font-bold">{weights.ctrl}%</span>
              </div>
              <input
                type="range"
                min="5"
                max="25"
                value={weights.ctrl}
                onChange={(e) => setWeights({ ...weights, ctrl: Number(e.target.value) })}
                className="w-full h-1.5 bg-slate-800 rounded appearance-none cursor-pointer accent-emerald-500"
              />
              <div className="text-[11px] font-mono text-slate-300">{controls.length} Deployed</div>
            </div>

            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
              <div className="flex justify-between text-[10px] font-mono text-slate-400">
                <span>Incidents</span>
                <span className="text-blue-400 font-bold">{weights.incident}%</span>
              </div>
              <input
                type="range"
                min="0"
                max="20"
                value={weights.incident}
                onChange={(e) => setWeights({ ...weights, incident: Number(e.target.value) })}
                className="w-full h-1.5 bg-slate-800 rounded appearance-none cursor-pointer accent-blue-500"
              />
              <div className="text-[11px] font-mono text-slate-300">Active Impact</div>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-cyan-300 flex items-center justify-between">
            <span>Formula: Risk = ({weights.auth}% Auth) + ({weights.network}% Net) + ({weights.data}% Data) + ({weights.vuln}% Vulns) + ({weights.ctrl}% Controls) + ({weights.incident}% Incidents)</span>
          </div>
        </div>
      </div>

      {/* Row 2: Explainable Waterfall Chart of Risk Contributors */}
      {(() => {
        const contributors = riskData.contributors || [
          { id: 'rc-1', name: 'Suspicious Authentication', points: 25, category: 'Authentication', description: 'Multiple failed logins and unrecognized offshore device access.' },
          { id: 'rc-2', name: 'Privilege Escalation', points: 20, category: 'Identity', description: 'Standard admin elevated to Domain Super Administrator.' },
          { id: 'rc-3', name: 'Unusual Data Transfer', points: 18, category: 'Data Exfiltration', description: '4.8 GB outbound HTTPS transfer to external cloud storage endpoint.' },
          { id: 'rc-4', name: 'Unknown Device', points: 10, category: 'Endpoints', description: 'New device hardware hash initialized SSO token without MFA.' }
        ];

        const contributorSum = contributors.reduce((s, c) => s + c.points, 0);
        const baselinePosture = Math.max(10, customCalculatedScore - contributorSum);

        const waterfallData = [
          {
            name: 'Base Posture',
            displayValue: `${baselinePosture}`,
            placeholder: 0,
            value: baselinePosture,
            total: baselinePosture,
            fill: '#0284c7',
            isDelta: false
          },
          ...contributors.map((c, idx) => {
            const prev = idx === 0
              ? baselinePosture
              : baselinePosture + contributors.slice(0, idx).reduce((acc, curr) => acc + curr.points, 0);
            const colors = ['#f43f5e', '#ea580c', '#eab308', '#a855f7'];
            return {
              name: c.name,
              displayValue: `+${c.points}`,
              placeholder: prev,
              value: c.points,
              total: prev + c.points,
              fill: colors[idx % colors.length],
              isDelta: true
            };
          }),
          {
            name: 'Total Risk',
            displayValue: `=${customCalculatedScore}`,
            placeholder: 0,
            value: customCalculatedScore,
            total: customCalculatedScore,
            fill: customCalculatedScore >= 80 ? '#dc2626' : customCalculatedScore >= 65 ? '#ea580c' : '#16a34a',
            isDelta: false
          }
        ];

        return (
          <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
                  <BarChart3 className="w-4 h-4 text-cyan-400" />
                  <span>EXPLAINABLE RISK CONTRIBUTOR WATERFALL</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Step-by-step mathematical attribution of why risk elevated from baseline posture to {customCalculatedScore}/100.
                </p>
              </div>
              <div className="flex items-center space-x-2 text-xs font-mono">
                <span className="text-slate-400">Total Increment:</span>
                <span className="font-bold text-rose-400">+{contributorSum} Points</span>
              </div>
            </div>

            {/* Recharts Waterfall Floating Stacked Bar Chart */}
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={waterfallData} margin={{ top: 20, right: 30, left: 10, bottom: 25 }}>
                  <XAxis
                    dataKey="name"
                    stroke="#64748b"
                    fontSize={11}
                    fontFamily="monospace"
                    interval={0}
                    angle={-15}
                    textAnchor="end"
                  />
                  <YAxis
                    stroke="#64748b"
                    fontSize={11}
                    fontFamily="monospace"
                    domain={[0, 100]}
                  />
                  <Tooltip
                    content={({ active, payload }) => {
                      if (active && payload && payload.length) {
                        const data = payload[0].payload;
                        return (
                          <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl shadow-xl text-xs font-mono">
                            <div className="font-bold text-slate-200">{data.name}</div>
                            <div className="text-cyan-400 mt-1">Impact: {data.displayValue} points</div>
                            <div className="text-slate-400">Cumulative: {data.total} / 100</div>
                          </div>
                        );
                      }
                      return null;
                    }}
                  />
                  {/* Transparent Floating Base Bar */}
                  <Bar dataKey="placeholder" stackId="waterfall" fill="transparent" />
                  {/* Visible Value Bar */}
                  <Bar dataKey="value" stackId="waterfall" radius={[6, 6, 0, 0]}>
                    {waterfallData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            {/* Contributor Root-Cause Attribution Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-2 font-mono text-xs">
              {contributors.map((c, i) => {
                const borderColors = ['border-rose-800/80', 'border-orange-800/80', 'border-amber-800/80', 'border-purple-800/80'];
                const textColors = ['text-rose-400', 'text-orange-400', 'text-amber-400', 'text-purple-400'];
                return (
                  <div key={c.id || i} className={`p-3.5 rounded-xl bg-slate-900/90 border ${borderColors[i % borderColors.length]} space-y-1.5`}>
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] text-slate-500 uppercase">{c.category}</span>
                      <span className={`font-black ${textColors[i % textColors.length]}`}>+{c.points} pts</span>
                    </div>
                    <div className="font-bold text-slate-200 truncate">{c.name}</div>
                    <p className="text-[10px] text-slate-400 font-sans leading-relaxed">{c.description}</p>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })()}

      {/* Row 3: Editable Org Profile & Security Controls Manager */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Editable Organization Profile */}
        <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
              <Building2 className="w-4 h-4 text-cyan-400" />
              <span>EDIT CYBER PROFILE ({activeOrg.name})</span>
            </h3>
          </div>

          <form onSubmit={handleSave} className="space-y-4 text-xs">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-slate-400 font-mono mb-1">User Count</label>
                <input
                  type="number"
                  value={formData.usersCount}
                  onChange={(e) => setFormData({ ...formData, usersCount: Number(e.target.value) })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-400 font-mono mb-1">Critical Systems</label>
                <input
                  type="number"
                  value={formData.criticalSystems}
                  onChange={(e) => setFormData({ ...formData, criticalSystems: Number(e.target.value) })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-400 font-mono mb-1">Internet Facing Services</label>
                <input
                  type="number"
                  value={formData.internetFacingServices}
                  onChange={(e) => setFormData({ ...formData, internetFacingServices: Number(e.target.value) })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-400 font-mono mb-1">Known Vulnerabilities</label>
                <input
                  type="number"
                  value={formData.knownVulnerabilities}
                  onChange={(e) => setFormData({ ...formData, knownVulnerabilities: Number(e.target.value) })}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>

            <div>
              <label className="block text-slate-400 font-mono mb-1">Data Sensitivity Level</label>
              <select
                value={formData.dataSensitivity}
                onChange={(e) => setFormData({ ...formData, dataSensitivity: e.target.value as any })}
                className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
              >
                <option value="LOW">LOW</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="HIGH">HIGH</option>
                <option value="CRITICAL">CRITICAL</option>
              </select>
            </div>

            <button
              type="submit"
              disabled={isUpdating}
              className="w-full py-2.5 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 font-bold text-xs"
            >
              Apply Profile Parameters & Recalculate Score
            </button>
          </form>
        </div>

        {/* Security Controls Manager */}
        <div className="glass-panel p-6 rounded-2xl border border-emerald-500/30 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span>DEPLOYED SECURITY CONTROLS</span>
            </h3>
            <span className="text-xs font-mono text-emerald-400">{controls.length} Active Controls</span>
          </div>

          <div className="space-y-2 max-h-48 overflow-y-auto">
            {controls.map((ctrl, i) => (
              <div key={i} className="flex items-center justify-between p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs">
                <span className="font-semibold text-slate-200 flex items-center space-x-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>{ctrl}</span>
                </span>
                <button
                  onClick={() => handleRemoveControl(i)}
                  className="text-slate-500 hover:text-rose-400"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>

          <div className="flex items-center space-x-2 pt-2">
            <input
              type="text"
              placeholder="e.g. FIDO2 WebAuthn Keys, Zero Trust Microsegmentation..."
              value={newControl}
              onChange={(e) => setNewControl(e.target.value)}
              className="flex-1 px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
            <button
              onClick={handleAddControl}
              className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs flex items-center space-x-1 shrink-0"
            >
              <Plus className="w-4 h-4" />
              <span>Deploy</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
