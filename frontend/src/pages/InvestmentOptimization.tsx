import React, { useState, useEffect } from 'react';
import {
  TrendingUp,
  IndianRupee,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Info,
  Sliders,
  DollarSign,
  PieChart as PieChartIcon,
  Sparkles,
  RefreshCw,
  Layers,
  Building2,
  ShieldCheck,
  Zap
} from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';

export interface InvestmentRecommendation {
  id: string;
  cveId: string;
  title: string;
  severity: string;
  cvssScore: number;
  cyberGuardPriority: string;
  cyberGuardScore: number;
  affectedVendor: string;
  affectedProduct: string;
  knownExploited: boolean;
  exploitAvailable: boolean;
  estimatedCost: number;
  costLabel: string;
  isCostEstimated: boolean;
  expectedRiskReduction: number;
  efficiencyScore: number;
  priorityRank: number;
  selectionStatus: 'SELECTED' | 'OUTSIDE_BUDGET';
  justificationReason: string;
}

export interface OptimizationResult {
  budget: number;
  totalInvested: number;
  totalRiskReduced: number;
  remainingBudget: number;
  selectedCount: number;
  totalEvaluated: number;
  recommendations: InvestmentRecommendation[];
  chartData: {
    step: number;
    allocatedBudget: number;
    cumulativeRiskReduction: number;
    cveId: string;
  }[];
  explanation: string;
}

import { useApp } from '../context/AppContext';

export const InvestmentOptimization: React.FC = () => {
  const { isDemoActive, demoStep } = useApp();
  const [budgetInput, setBudgetInput] = useState<string>('1000000');
  const [minCvss, setMinCvss] = useState<string>('0');
  const [knownExploitedOnly, setKnownExploitedOnly] = useState<boolean>(false);
  const [result, setResult] = useState<OptimizationResult | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Automated Demo Triggers for Screen Recording
  useEffect(() => {
    if (isDemoActive) {
      if (demoStep === 10) {
        setBudgetInput('1000000');
      } else if (demoStep === 15) {
        // Scene 15: Dynamic what-if analysis - start at 500,000 then shift to 2,000,000
        setBudgetInput('500000');
        const timer1 = setTimeout(() => {
          setBudgetInput('2000000');
        }, 7000);
        return () => clearTimeout(timer1);
      }
    }
  }, [isDemoActive, demoStep]);

  const fetchOptimization = async (budgetVal: number, cvssVal?: number, kevOnly?: boolean) => {
    try {
      setIsLoading(true);
      setError(null);
      const res = await fetch('/api/investment-optimization', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          budget: budgetVal,
          minCvss: cvssVal && cvssVal > 0 ? cvssVal : undefined,
          knownExploitedOnly: kevOnly
        })
      }).then((r) => r.json());

      if (res && res.recommendations) {
        setResult(res);
      } else {
        setError('Failed to calculate investment optimization.');
      }
    } catch (err: any) {
      setError(err.message || 'Error fetching optimization results');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    const numericBudget = parseFloat(budgetInput) || 0;
    fetchOptimization(numericBudget, parseFloat(minCvss) || 0, knownExploitedOnly);
  }, [budgetInput, minCvss, knownExploitedOnly]);

  const handlePresetBudget = (amount: number) => {
    setBudgetInput(String(amount));
  };

  const formatCurrency = (val: number) => {
    return `₹${val.toLocaleString('en-IN')}`;
  };

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 sm:space-y-8 max-w-7xl mx-auto">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-slate-900 via-[#0F172A] to-slate-900 border border-slate-800/80 p-4 sm:p-6 rounded-2xl shadow-xl">
        <div>
          <div className="flex items-center space-x-3 mb-2">
            <div className="p-2 sm:p-2.5 rounded-xl bg-gradient-to-br from-emerald-500/20 to-teal-500/10 border border-emerald-500/30 text-emerald-400 shrink-0">
              <TrendingUp className="w-5 h-5 sm:w-6 sm:h-6" />
            </div>
            <div>
              <h1 className="text-xl sm:text-2xl font-bold text-slate-100 tracking-tight">Investment Optimization Engine</h1>
              <p className="text-[11px] sm:text-xs font-mono text-slate-400">Algorithmic Cybersecurity Resource Allocation & Risk-Reduction Optimization</p>
            </div>
          </div>
          <p className="text-xs sm:text-sm text-slate-300 max-w-3xl leading-relaxed">
            Given limited cybersecurity resources or budget, CyberGuard Grid evaluates real vulnerability threat intelligence stored in MySQL to mathematically determine which remediations yield the highest justified risk reduction per rupee invested.
          </p>
        </div>

        <div className="flex items-center space-x-3 shrink-0">
          <button
            onClick={() => fetchOptimization(parseFloat(budgetInput) || 0, parseFloat(minCvss) || 0, knownExploitedOnly)}
            className="w-full sm:w-auto px-4 py-2 bg-emerald-600/20 hover:bg-emerald-600/30 border border-emerald-500/40 text-emerald-300 rounded-xl text-xs font-semibold flex items-center justify-center space-x-2 transition"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Recalculate</span>
          </button>
        </div>
      </div>

      {/* Budget & Parameter Controller */}
      <div className="bg-slate-900/90 border border-slate-800/80 p-4 sm:p-6 rounded-2xl space-y-6 shadow-lg">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
          <h2 className="text-sm sm:text-base font-bold text-slate-200 flex items-center space-x-2">
            <Sliders className="w-4 h-4 sm:w-5 sm:h-5 text-emerald-400 shrink-0" />
            <span>Cybersecurity Budget & Optimization Parameters</span>
          </h2>
          <span className="text-[10px] sm:text-xs font-mono text-slate-400 bg-slate-800/60 px-3 py-1 rounded-full border border-slate-700">
            Real MySQL Vulnerability Input
          </span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Budget Input Field */}
          <div className="space-y-2">
            <label className="text-xs font-semibold text-slate-300 block uppercase tracking-wider font-mono">
              Available Cybersecurity Budget (₹ INR)
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-emerald-400 font-bold">
                ₹
              </div>
              <input
                type="number"
                value={budgetInput}
                onChange={(e) => setBudgetInput(e.target.value)}
                placeholder="Enter budget e.g. 1000000"
                className="w-full pl-9 pr-4 py-3 bg-slate-950 border border-slate-700/80 rounded-xl text-slate-100 font-mono text-sm sm:text-base focus:outline-none focus:border-emerald-500 transition"
              />
            </div>
            {/* Quick Presets */}
            <div className="flex flex-wrap items-center gap-1.5 pt-1">
              <span className="text-[10px] text-slate-400 font-mono mr-1">Presets:</span>
              {[200000, 500000, 1000000, 2500000].map((preset) => (
                <button
                  key={preset}
                  onClick={() => handlePresetBudget(preset)}
                  className={`px-2.5 py-1 text-[11px] font-mono rounded border transition ${
                    parseFloat(budgetInput) === preset
                      ? 'bg-emerald-950/80 text-emerald-400 border-emerald-700'
                      : 'bg-slate-800/50 text-slate-400 border-slate-700 hover:text-slate-200'
                  }`}
                >
                  ₹{(preset / 100000).toFixed(0)}L
                </button>
              ))}
            </div>
          </div>

          {/* Filters */}
          <div className="space-y-2">
            <label className="text-xs font-semibold text-slate-300 block uppercase tracking-wider font-mono">
              Severity & Weaponization Filter
            </label>
            <div className="flex flex-col space-y-3 pt-1">
              <label className="flex items-center space-x-3 cursor-pointer text-xs text-slate-300">
                <input
                  type="checkbox"
                  checked={knownExploitedOnly}
                  onChange={(e) => setKnownExploitedOnly(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-950 text-emerald-500 focus:ring-emerald-500"
                />
                <span className="flex items-center space-x-1.5">
                  <Flame className="w-4 h-4 text-rose-400 shrink-0" />
                  <span>Prioritize CISA Known Exploited (KEV) Only</span>
                </span>
              </label>

              <div className="flex flex-wrap items-center gap-2 text-xs text-slate-300">
                <span className="text-slate-400">Min CVSS Score:</span>
                <select
                  value={minCvss}
                  onChange={(e) => setMinCvss(e.target.value)}
                  className="bg-slate-950 border border-slate-700/80 rounded-lg px-3 py-1 text-slate-200 font-mono text-xs focus:outline-none focus:border-emerald-500"
                >
                  <option value="0">All CVSS (0.0+)</option>
                  <option value="4">Medium (4.0+)</option>
                  <option value="7">High (7.0+)</option>
                  <option value="9">Critical (9.0+)</option>
                </select>
              </div>
            </div>
          </div>

          {/* Strategy Justification */}
          <div className="bg-slate-950/60 border border-slate-800 p-4 rounded-xl space-y-2 text-xs text-slate-400">
            <div className="flex items-center space-x-2 text-emerald-400 font-semibold">
              <Sparkles className="w-4 h-4 shrink-0" />
              <span>Optimization Concept</span>
            </div>
            <p className="leading-relaxed">
              Uses an explainable <strong>Greedy Knapsack Algorithm</strong>: Items are ranked by <code>Risk Reduction / Remediation Cost</code> with high priority multipliers assigned to weaponized CISA KEV advisories.
            </p>
          </div>
        </div>
      </div>

      {/* Metric Cards Summary */}
      {result && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6">
          {/* Card 1: Total Budget */}
          <div className="bg-slate-900/90 border border-slate-800 p-4 sm:p-5 rounded-2xl space-y-2">
            <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
              <span>TOTAL BUDGET</span>
              <IndianRupee className="w-4 h-4 text-slate-400" />
            </div>
            <div className="text-xl sm:text-2xl font-bold text-slate-100 font-mono">
              {formatCurrency(result.budget)}
            </div>
            <div className="text-[11px] text-slate-500 font-mono">User-Provided Allocation</div>
          </div>

          {/* Card 2: Recommended Investment */}
          <div className="bg-slate-900/90 border border-emerald-900/40 p-4 sm:p-5 rounded-2xl space-y-2">
            <div className="flex items-center justify-between text-emerald-400 text-xs font-mono">
              <span>RECOMMENDED INVESTMENT</span>
              <Zap className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="text-xl sm:text-2xl font-bold text-emerald-400 font-mono">
              {formatCurrency(result.totalInvested)}
            </div>
            <div className="text-[11px] text-emerald-500/90 font-mono">
              {result.selectedCount} of {result.totalEvaluated} remediations selected
            </div>
          </div>

          {/* Card 3: Expected Risk Reduction */}
          <div className="bg-slate-900/90 border border-cyan-900/40 p-4 sm:p-5 rounded-2xl space-y-2">
            <div className="flex items-center justify-between text-cyan-400 text-xs font-mono">
              <span>EXPECTED RISK REDUCTION</span>
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-xl sm:text-2xl font-bold text-cyan-400 font-mono">
              +{result.totalRiskReduced} <span className="text-xs font-normal">pts</span>
            </div>
            <div className="text-[11px] text-cyan-500/90 font-mono">Quantified Threat Mitigation</div>
          </div>

          {/* Card 4: Remaining Budget */}
          <div className="bg-slate-900/90 border border-slate-800 p-4 sm:p-5 rounded-2xl space-y-2">
            <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
              <span>REMAINING BUDGET</span>
              <Building2 className="w-4 h-4 text-slate-400" />
            </div>
            <div className="text-xl sm:text-2xl font-bold text-slate-200 font-mono">
              {formatCurrency(result.remainingBudget)}
            </div>
            <div className="text-[11px] text-slate-500 font-mono">Unallocated Reserve</div>
          </div>
        </div>
      )}

      {/* Chart Section: Investment vs Expected Risk Reduction */}
      {result && result.chartData && result.chartData.length > 1 && (
        <div className="bg-slate-900/90 border border-slate-800 p-4 sm:p-6 rounded-2xl space-y-4 shadow-lg">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-bold text-slate-200 flex items-center space-x-2">
                <PieChartIcon className="w-4 h-4 text-cyan-400 shrink-0" />
                <span>Investment Allocated vs Expected Risk Reduction</span>
              </h3>
              <p className="text-xs text-slate-400 font-mono">Calculated backend curve mapping cumulative risk points saved against budget deployment.</p>
            </div>
            <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 px-3 py-1 rounded-full border border-cyan-800/80">
              Live Backend Calculation
            </span>
          </div>

          <div className="h-48 sm:h-64 w-full pt-4">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={result.chartData} margin={{ top: 10, right: 20, left: -10, bottom: 0 }}>
                <defs>
                  <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10B981" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#10B981" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" />
                <XAxis dataKey="allocatedBudget" stroke="#64748B" tickFormatter={(v) => `₹${(v / 1000).toFixed(0)}k`} />
                <YAxis stroke="#64748B" label={{ value: 'Risk Reduction Points', angle: -90, position: 'insideLeft', fill: '#94A3B8' }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0B0F17', borderColor: '#334155', borderRadius: '12px', fontSize: '12px' }}
                  formatter={(value: any, name: string) => [
                    name === 'cumulativeRiskReduction' ? `+${value} pts` : formatCurrency(value),
                    name === 'cumulativeRiskReduction' ? 'Risk Reduction' : 'Allocated Budget'
                  ]}
                  labelFormatter={(v) => `Allocated Budget: ${formatCurrency(Number(v))}`}
                />
                <Area type="monotone" dataKey="cumulativeRiskReduction" stroke="#10B981" strokeWidth={2} fillOpacity={1} fill="url(#riskGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Recommended Security Investments Table */}
      {result && (
        <div className="bg-slate-900/90 border border-slate-800 p-6 rounded-2xl space-y-4 shadow-lg">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-bold text-slate-200 flex items-center space-x-2">
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                <span>Recommended Security Investments</span>
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Order of prioritized remediations calculated to maximize overall risk reduction under current budget constraints.
              </p>
            </div>
            <div className="text-xs font-mono text-slate-400">
              Showing {result.recommendations.length} Evaluated Actions
            </div>
          </div>

          <div className="overflow-x-auto rounded-xl border border-slate-800">
            <table className="w-full text-left text-xs font-sans">
              <thead className="bg-slate-950/80 text-slate-400 font-mono uppercase text-[11px] border-b border-slate-800">
                <tr>
                  <th className="p-3 text-center w-12">Priority</th>
                  <th className="p-3">Vulnerability / CVE</th>
                  <th className="p-3">Severity</th>
                  <th className="p-3">Affected Asset</th>
                  <th className="p-3">Investment Required</th>
                  <th className="p-3">Risk Reduction</th>
                  <th className="p-3">Selection Status</th>
                  <th className="p-3">Reason for Selection</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {result.recommendations.map((rec) => (
                  <tr
                    key={rec.id}
                    className={`transition hover:bg-slate-800/40 ${
                      rec.selectionStatus === 'SELECTED' ? 'bg-emerald-950/10' : 'opacity-65'
                    }`}
                  >
                    <td className="p-3 font-mono font-bold text-center text-slate-200">
                      #{rec.priorityRank}
                    </td>

                    <td className="p-3">
                      <div className="font-mono font-bold text-emerald-400 flex items-center space-x-1.5">
                        <span>{rec.cveId}</span>
                        {rec.knownExploited && (
                          <span className="px-1.5 py-0.5 text-[9px] bg-rose-950 text-rose-400 border border-rose-800 rounded font-sans">
                            KEV
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] text-slate-400 line-clamp-1 max-w-xs">{rec.title}</div>
                    </td>

                    <td className="p-3 font-mono">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                          rec.severity === 'CRITICAL'
                            ? 'bg-rose-950 text-rose-400 border-rose-800'
                            : rec.severity === 'HIGH'
                            ? 'bg-amber-950 text-amber-400 border-amber-800'
                            : 'bg-blue-950 text-blue-400 border-blue-800'
                        }`}
                      >
                        {rec.severity} ({rec.cvssScore})
                      </span>
                    </td>

                    <td className="p-3 font-mono text-slate-300">
                      <div>{rec.affectedVendor}</div>
                      <div className="text-[11px] text-slate-400">{rec.affectedProduct}</div>
                    </td>

                    <td className="p-3 font-mono">
                      <div className="font-bold text-slate-100">{formatCurrency(rec.estimatedCost)}</div>
                      {rec.isCostEstimated && (
                        <div className="text-[10px] text-slate-400 italic">Estimated</div>
                      )}
                    </td>

                    <td className="p-3 font-mono">
                      <span className="text-cyan-400 font-bold">+{rec.expectedRiskReduction} pts</span>
                      <div className="text-[10px] text-slate-400">
                        Score: {rec.efficiencyScore} pts/₹1L
                      </div>
                    </td>

                    <td className="p-3">
                      {rec.selectionStatus === 'SELECTED' ? (
                        <span className="inline-flex items-center px-2.5 py-1 rounded-full text-[10px] font-mono font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">
                          ✓ SELECTED
                        </span>
                      ) : (
                        <span className="inline-flex items-center px-2.5 py-1 rounded-full text-[10px] font-mono font-bold bg-slate-800 text-slate-400 border border-slate-700">
                          OUTSIDE BUDGET
                        </span>
                      )}
                    </td>

                    <td className="p-3 text-xs text-slate-400 max-w-xs leading-relaxed">
                      {rec.justificationReason}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Data Transparency Banner */}
      <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 text-slate-400 text-xs flex items-start space-x-3">
        <Info className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <p className="font-semibold text-slate-300">Transparency & Data Integrity Guarantee</p>
          <p className="leading-relaxed">
            All vulnerability records and CVSS metric vectors are pulled directly from live MySQL database storage. Where official vendor advisories omit direct remediation cost estimations, values are transparently marked as <code>(Estimated)</code> using standardized severity models. Weaponized vulnerabilities cataloged in CISA KEV receive priority weighting.
          </p>
        </div>
      </div>
    </div>
  );
};

export default InvestmentOptimization;
