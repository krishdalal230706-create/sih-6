import React, { useState, useEffect } from 'react';
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
  Landmark,
  Layers,
  Building2,
  Play,
  ShieldCheck,
  Database,
  Flame,
  Sparkles,
  Server,
  CreditCard,
  Smartphone,
  Monitor,
  Network,
  RotateCcw,
  CheckCircle,
  Clock,
  ChevronRight
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
  PolarRadiusAxis,
  BarChart,
  Bar,
  CartesianGrid
} from 'recharts';
import { useApp } from '../context/AppContext';
import { BankAsset, BankSecurityEvent } from '../types';

export const Overview: React.FC = () => {
  const {
    activeOrg,
    riskData,
    isLoading,
    executeResponseAction,
    responseActions,
    vulnerabilityStats,
    token,
    incidents,
    switchOrg
  } = useApp();
  const navigate = useNavigate();

  const [executingIdx, setExecutingIdx] = useState<number | null>(null);
  const [topRemediationMsg, setTopRemediationMsg] = useState<string | null>(null);
  const [bankAssets, setBankAssets] = useState<BankAsset[]>([]);
  const [securityEvents, setSecurityEvents] = useState<BankSecurityEvent[]>([]);
  const [loadingAssets, setLoadingAssets] = useState<boolean>(true);

  // Fraud rules & Demo tour state
  const [fraudRules, setFraudRules] = useState<any[]>([]);
  const [simulatingFraud, setSimulatingFraud] = useState(false);
  const [fraudSimMsg, setFraudSimMsg] = useState<string | null>(null);

  // 60-Second Guided Pitch Tour
  const [showDemoTour, setShowDemoTour] = useState(false);
  const [demoTourStep, setDemoTourStep] = useState<1 | 2 | 3 | 4>(1);
  const [demoInjecting, setDemoInjecting] = useState(false);
  const [demoRemediating, setDemoRemediating] = useState(false);
  const [demoFeedback, setDemoFeedback] = useState<string | null>(null);

  // Fetch Bank Assets, Security Events, and Fraud Rules
  const fetchBankData = async () => {
    if (!token) return;
    try {
      setLoadingAssets(true);
      const [assetsRes, eventsRes, rulesRes] = await Promise.all([
        fetch('/api/bank-assets', { headers: { Authorization: `Bearer ${token}` } }),
        fetch('/api/bank-assets/events?limit=8', { headers: { Authorization: `Bearer ${token}` } }),
        fetch('/api/bank-assets/fraud-rules', { headers: { Authorization: `Bearer ${token}` } })
      ]);

      if (assetsRes.ok) {
        const data = await assetsRes.json();
        setBankAssets(data.assets || []);
      }
      if (eventsRes.ok) {
        const eData = await eventsRes.json();
        setSecurityEvents(eData.events || []);
      }
      if (rulesRes.ok) {
        const rData = await rulesRes.json();
        setFraudRules(rData.rules || []);
      }
    } catch (err) {
      console.error('Failed to fetch Bank SOC telemetry:', err);
    } finally {
      setLoadingAssets(false);
    }
  };

  useEffect(() => {
    fetchBankData();
  }, [token]);

  // Simulate UPI Fraud burst
  const handleSimulateFraud = async () => {
    if (!token) return;
    try {
      setSimulatingFraud(true);
      const res = await fetch('/api/bank-assets/fraud-rules/simulate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        }
      });
      if (res.ok) {
        setFraudSimMsg('⚡ RULE-TXN-01 Triggered: UPI Micro-Debit Velocity Burst (420 debits/min)! Settlement hold enforced.');
        await fetchBankData();
        if (activeOrg) switchOrg(activeOrg.id);
        setTimeout(() => setFraudSimMsg(null), 5000);
      }
    } catch (err) {
      console.error('Failed to simulate fraud rule:', err);
    } finally {
      setSimulatingFraud(false);
    }
  };

  // Demo Tour Step 2: Trigger Attack
  const handleDemoAttackTrigger = async () => {
    if (!token) return;
    try {
      setDemoInjecting(true);
      const res = await fetch('/api/bank-assets/simulate-scenario', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ scenarioId: 'scenario-3' })
      });
      if (res.ok) {
        setDemoFeedback('⚡ Adversary Scenario 3 Injected: Payment Gateway compromised (+35 pts risk). Move to Step 3 for CERT-In notification.');
        setDemoTourStep(3);
        await fetchBankData();
        if (activeOrg) switchOrg(activeOrg.id);
      }
    } catch (err) {
      console.error('Demo attack injection failed:', err);
    } finally {
      setDemoInjecting(false);
    }
  };

  // Demo Tour Step 4: Remediate Incident
  const handleDemoRemediate = async () => {
    if (!token) return;
    try {
      setDemoRemediating(true);
      const res = await fetch('/api/bank-assets/remediate-incident', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ assetId: 'asset-payment' })
      });
      if (res.ok) {
        setDemoFeedback('✓ Automated Countermeasure Deployed: Payment Gateway restored to HEALTHY! Cyber risk posture returned to baseline.');
        await fetchBankData();
        if (activeOrg) switchOrg(activeOrg.id);
      }
    } catch (err) {
      console.error('Demo remediation failed:', err);
    } finally {
      setDemoRemediating(false);
    }
  };

  const currentRiskScore = riskData?.overallRiskScore ?? activeOrg?.riskScore ?? 84;
  const currentSeverity =
    riskData?.severity ??
    (currentRiskScore >= 80 ? 'CRITICAL' : currentRiskScore >= 65 ? 'HIGH' : currentRiskScore >= 45 ? 'MEDIUM' : 'LOW');
  const scoreColor =
    currentRiskScore >= 80 ? '#f43f5e' : currentRiskScore >= 65 ? '#f59e0b' : currentRiskScore >= 45 ? '#eab308' : '#10b981';

  // Circular HUD gauge
  const gaugeRadius = 44;
  const gaugeCircumference = 2 * Math.PI * gaugeRadius;
  const gaugeOffset = gaugeCircumference - (gaugeCircumference * Math.min(100, Math.max(0, currentRiskScore))) / 100;

  // 10-Category Banking Radar Chart
  const bScores = riskData?.bankingCategoryScores;
  const radarData = [
    { category: 'Auth & HSM', risk: bScores?.authentication ?? 25, defense: Math.max(10, 100 - (bScores?.authentication ?? 25)) },
    { category: 'Core Banking', risk: bScores?.coreBanking ?? 28, defense: Math.max(10, 100 - (bScores?.coreBanking ?? 28)) },
    { category: 'Payment GW', risk: bScores?.paymentGateway ?? 88, defense: Math.max(10, 100 - (bScores?.paymentGateway ?? 88)) },
    { category: 'Customer CIF', risk: bScores?.customerData ?? 35, defense: Math.max(10, 100 - (bScores?.customerData ?? 35)) },
    { category: 'Network Core', risk: bScores?.networkSecurity ?? 30, defense: Math.max(10, 100 - (bScores?.networkSecurity ?? 30)) },
    { category: 'Workstations', risk: bScores?.endpointSecurity ?? 58, defense: Math.max(10, 100 - (bScores?.endpointSecurity ?? 58)) },
    { category: 'ATM Switch', risk: bScores?.atmSecurity ?? 40, defense: Math.max(10, 100 - (bScores?.atmSecurity ?? 40)) },
    { category: 'Third-Party', risk: bScores?.thirdParty ?? 35, defense: Math.max(10, 100 - (bScores?.thirdParty ?? 35)) }
  ];

  const trendData = [
    { time: '04:00', score: 62 },
    { time: '06:00', score: 64 },
    { time: '08:00', score: 72 },
    { time: '09:00', score: 78 },
    { time: '09:30', score: 84 },
    { time: '09:44', score: currentRiskScore }
  ];

  // Asset vulnerabilities chart data
  const assetVulnChartData = bankAssets.slice(0, 7).map((a) => ({
    name: a.name.split(' ')[0],
    risk: a.riskScore,
    vulns: a.associatedVulnsCount
  }));

  // KPI Calculations
  const criticalAlertsCount = securityEvents.filter((e) => e.severity === 'CRITICAL').length || activeOrg?.activeThreatsCount?.critical || 3;
  const activeIncidentsList = incidents.filter((i) => i.status !== 'Resolved');
  const activeIncidentsCount = activeIncidentsList.length || 2;
  const totalAssetsCount = bankAssets.length || 10;
  const vulnerableAssetsCount = bankAssets.filter((a) => a.securityStatus === 'COMPROMISED' || a.securityStatus === 'AT_RISK' || a.associatedVulnsCount > 0).length || 5;
  const resolvedIncidentsCount = incidents.filter((i) => i.status === 'Resolved').length || 4;
  const orgResponseActions = responseActions.filter((a) => a.orgId === (activeOrg?.id || 'org-1'));
  const pendingRemediationsCount = orgResponseActions.filter((a) => a.status !== 'Completed').length || 3;
  const displayActions = orgResponseActions.slice(0, 4);

  // Key Banking Assets for Overview
  const featuredAssetIds = ['asset-cbs', 'asset-payment', 'asset-atm', 'asset-mobile', 'asset-netbank', 'asset-custdb', 'asset-auth'];
  const featuredAssets = bankAssets.filter((a) => featuredAssetIds.includes(a.id)).slice(0, 7);

  const handleTopActionClick = async (idx: number) => {
    const act = displayActions[idx];
    if (act && act.status !== 'Completed') {
      setExecutingIdx(idx);
      const res = await executeResponseAction(act.id, act.incidentId);
      setExecutingIdx(null);

      if (res?.riskReduction) {
        setTopRemediationMsg(
          `✓ Remediation Action Executed! Bank Cyber Risk score reduced from ${res.riskReduction.previousScore} to ${res.riskReduction.newScore} (-${res.riskReduction.pointsReduced} pts).`
        );
      } else {
        setTopRemediationMsg(`✓ Remediation Action Executed! Demo Bank defense posture improved.`);
      }
    }
  };

  const getAssetIcon = (category: string) => {
    switch (category.toLowerCase()) {
      case 'core banking':
        return <Landmark className="w-4 h-4 text-cyan-400" />;
      case 'payment gateway':
        return <CreditCard className="w-4 h-4 text-purple-400" />;
      case 'atm infrastructure':
        return <Building2 className="w-4 h-4 text-amber-400" />;
      case 'mobile banking':
        return <Smartphone className="w-4 h-4 text-emerald-400" />;
      case 'customer database':
        return <Database className="w-4 h-4 text-rose-400" />;
      case 'workstations & endpoints':
        return <Monitor className="w-4 h-4 text-blue-400" />;
      case 'authentication server':
        return <Lock className="w-4 h-4 text-yellow-400" />;
      default:
        return <Server className="w-4 h-4 text-slate-400" />;
    }
  };

  const getStatusBadge = (status: BankAsset['securityStatus']) => {
    switch (status) {
      case 'HEALTHY':
        return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"><ShieldCheck className="w-2.5 h-2.5" /> Healthy</span>;
      case 'DEGRADED':
        return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-yellow-500/10 text-yellow-400 border border-yellow-500/20"><AlertTriangle className="w-2.5 h-2.5" /> Degraded</span>;
      case 'AT_RISK':
        return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20"><ShieldAlert className="w-2.5 h-2.5" /> At Risk</span>;
      case 'COMPROMISED':
        return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20 animate-pulse"><AlertTriangle className="w-2.5 h-2.5" /> Compromised</span>;
      case 'MAINTENANCE':
        return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-500/10 text-slate-400 border border-slate-500/20">Maintenance</span>;
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">MEDIUM</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-500/20 text-slate-400 border border-slate-500/30">LOW</span>;
    }
  };

  if (isLoading || !activeOrg) {
    return (
      <div className="p-8 flex items-center justify-center text-slate-400 font-mono">
        <Activity className="w-6 h-6 animate-spin text-cyan-400 mr-2" />
        <span>Ingesting Demo Bank SOC Telemetry...</span>
      </div>
    );
  }

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 max-w-7xl mx-auto">
      {/* Top Header Card */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex flex-wrap items-center gap-2.5 sm:gap-3">
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-100 uppercase flex items-center gap-2">
              <Landmark className="w-6 h-6 text-cyan-400" />
              Demo Bank SOC Operations Center
            </h1>
            <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-mono bg-cyan-950 text-cyan-400 border border-cyan-800">
              ● BANKING SECURITY EDITION
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time Threat Monitoring, Banking Asset Telemetry & Cyber Risk Quantification for{' '}
            <strong className="text-slate-200">Demo Bank (org-1)</strong> • Scheduled Commercial Bank (BFSI, India).
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 sm:gap-3 w-full sm:w-auto">
          <button
            onClick={() => setShowDemoTour(true)}
            className="px-3.5 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs glow-cyan transition-all flex items-center space-x-2 shadow-lg"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>60-Sec Bank SOC Demo Tour</span>
          </button>

          <div
            onClick={() => navigate('/bank-assets')}
            className="px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-800 hover:border-cyan-500/50 cursor-pointer flex items-center space-x-2.5 flex-1 sm:flex-initial transition-all"
          >
            <Server className="w-4 h-4 text-cyan-400 shrink-0" />
            <div className="min-w-0">
              <div className="text-[10px] font-mono text-slate-500 uppercase truncate">Assets Monitored</div>
              <div className="text-xs font-bold text-slate-200 truncate">{totalAssetsCount} Banking Systems</div>
            </div>
          </div>

          <div className="px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-800 flex items-center space-x-2.5 flex-1 sm:flex-initial">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse shrink-0"></span>
            <div className="min-w-0">
              <div className="text-[10px] font-mono text-slate-500 uppercase truncate">SOC Posture</div>
              <div className="text-xs font-bold text-emerald-400 truncate">● Active Defense</div>
            </div>
          </div>
        </div>
      </div>

      {/* 7 Main KPI Cards Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
        {/* KPI 1: Overall Risk Score */}
        <div
          onClick={() => navigate('/cyber-risk')}
          className="p-3.5 rounded-xl bg-gradient-to-br from-rose-950/30 to-slate-900 border border-rose-500/30 hover:border-rose-500 cursor-pointer transition-all flex flex-col justify-between"
        >
          <span className="text-[10px] font-mono uppercase text-slate-400 font-semibold truncate">Risk Score</span>
          <div className="my-1.5 flex items-baseline justify-between">
            <span className="text-2xl font-black font-mono" style={{ color: scoreColor }}>
              {currentRiskScore}
            </span>
            <span className="text-[9px] font-bold font-mono px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-400">
              {currentSeverity}
            </span>
          </div>
          <span className="text-[10px] text-slate-500">10-Factor Model</span>
        </div>

        {/* KPI 2: Critical Alerts */}
        <div
          onClick={() => navigate('/threat-detection')}
          className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 hover:border-rose-500/50 cursor-pointer transition-all flex flex-col justify-between"
        >
          <span className="text-[10px] font-mono uppercase text-slate-400 font-semibold truncate">Critical Alerts</span>
          <div className="my-1.5 flex items-baseline justify-between">
            <span className="text-2xl font-black font-mono text-rose-400">{criticalAlertsCount}</span>
            <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <span className="text-[10px] text-rose-400/80">Immediate attention</span>
        </div>

        {/* KPI 3: Active Incidents */}
        <div
          onClick={() => navigate('/incidents')}
          className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 hover:border-amber-500/50 cursor-pointer transition-all flex flex-col justify-between"
        >
          <span className="text-[10px] font-mono uppercase text-slate-400 font-semibold truncate">Active Incidents</span>
          <div className="my-1.5 flex items-baseline justify-between">
            <span className="text-2xl font-black font-mono text-amber-400">{activeIncidentsCount}</span>
            <Radio className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <span className="text-[10px] text-amber-400/80">In containment</span>
        </div>

        {/* KPI 4: Total Monitored Assets */}
        <div
          onClick={() => navigate('/bank-assets')}
          className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 hover:border-cyan-500/50 cursor-pointer transition-all flex flex-col justify-between"
        >
          <span className="text-[10px] font-mono uppercase text-slate-400 font-semibold truncate">Monitored Assets</span>
          <div className="my-1.5 flex items-baseline justify-between">
            <span className="text-2xl font-black font-mono text-cyan-400">{totalAssetsCount}</span>
            <Server className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <span className="text-[10px] text-cyan-400/80">Tier-1 & Tier-2</span>
        </div>

        {/* KPI 5: Vulnerable Assets */}
        <div
          onClick={() => navigate('/bank-assets')}
          className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 hover:border-amber-500/50 cursor-pointer transition-all flex flex-col justify-between"
        >
          <span className="text-[10px] font-mono uppercase text-slate-400 font-semibold truncate">Vulnerable Assets</span>
          <div className="my-1.5 flex items-baseline justify-between">
            <span className="text-2xl font-black font-mono text-orange-400">{vulnerableAssetsCount}</span>
            <ShieldAlert className="w-3.5 h-3.5 text-orange-400" />
          </div>
          <span className="text-[10px] text-slate-500">Unpatched CVEs</span>
        </div>

        {/* KPI 6: Resolved Incidents */}
        <div
          onClick={() => navigate('/incidents')}
          className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 hover:border-emerald-500/50 cursor-pointer transition-all flex flex-col justify-between"
        >
          <span className="text-[10px] font-mono uppercase text-slate-400 font-semibold truncate">Resolved Incidents</span>
          <div className="my-1.5 flex items-baseline justify-between">
            <span className="text-2xl font-black font-mono text-emerald-400">{resolvedIncidentsCount}</span>
            <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <span className="text-[10px] text-emerald-400/80">Post-incident closed</span>
        </div>

        {/* KPI 7: Pending Remediation Actions */}
        <div
          onClick={() => navigate('/response-center')}
          className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 hover:border-blue-500/50 cursor-pointer transition-all flex flex-col justify-between"
        >
          <span className="text-[10px] font-mono uppercase text-slate-400 font-semibold truncate">Pending Actions</span>
          <div className="my-1.5 flex items-baseline justify-between">
            <span className="text-2xl font-black font-mono text-blue-400">{pendingRemediationsCount}</span>
            <Zap className="w-3.5 h-3.5 text-blue-400" />
          </div>
          <span className="text-[10px] text-blue-400/80">Playbook tasks</span>
        </div>
      </div>

      {/* Fraud Simulation Alert Banner */}
      {fraudSimMsg && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs font-mono flex items-center justify-between animate-fadeIn">
          <span className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            {fraudSimMsg}
          </span>
          <button
            onClick={() => navigate('/threat-detection')}
            className="px-2.5 py-1 rounded bg-rose-500/20 text-rose-300 font-bold hover:bg-rose-500/30 text-[10px]"
          >
            Investigate in Threat Sentry →
          </button>
        </div>
      )}

      {/* Banking Transaction Fraud Rules Sentry Strip */}
      <div className="glass-panel p-4 sm:p-5 rounded-2xl border border-purple-500/30 bg-gradient-to-r from-slate-950 via-slate-900 to-purple-950/20 shadow-xl space-y-3">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center space-x-2.5">
            <CreditCard className="w-5 h-5 text-purple-400" />
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
                  Banking Transaction Fraud Rules Sentry
                </h3>
                <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold bg-purple-950 text-purple-400 border border-purple-800">
                  REAL-TIME TXN TRIPWIRES
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Continuous algorithmic monitoring across NPCI UPI 2.0, ATM Switch NFS, and NetBanking RTGS/NEFT rails.
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2.5 w-full sm:w-auto">
            <button
              onClick={handleSimulateFraud}
              disabled={simulatingFraud}
              className="flex-1 sm:flex-initial px-3 py-1.5 rounded-lg bg-purple-500/10 hover:bg-purple-500/20 text-purple-400 border border-purple-500/30 text-xs font-mono font-bold transition-all flex items-center justify-center space-x-1.5 disabled:opacity-50"
            >
              <Zap className={`w-3.5 h-3.5 ${simulatingFraud ? 'animate-spin' : ''}`} />
              <span>{simulatingFraud ? 'Simulating Burst...' : 'Simulate UPI Fraud Burst'}</span>
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {fraudRules.length > 0 ? (
            fraudRules.map((rule: any) => (
              <div
                key={rule.id}
                className={`p-3.5 rounded-xl border space-y-2 transition-all ${
                  rule.status === 'TRIGGERED'
                    ? 'bg-rose-950/30 border-rose-500/40 shadow-lg shadow-rose-950/30 animate-pulse'
                    : 'bg-slate-900/60 border-slate-800/80 hover:border-slate-700'
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <span className="text-[10px] font-mono text-purple-400 font-bold">{rule.id}</span>
                    <h4 className="text-xs font-bold text-slate-200 mt-0.5">{rule.name}</h4>
                  </div>
                  <span
                    className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold shrink-0 border ${
                      rule.status === 'TRIGGERED'
                        ? 'bg-rose-950 text-rose-400 border-rose-800'
                        : 'bg-emerald-950 text-emerald-400 border-emerald-800'
                    }`}
                  >
                    ● {rule.status}
                  </span>
                </div>

                <p className="text-[11px] text-slate-400 leading-relaxed">{rule.description}</p>

                <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-400">
                  <span>Threshold: <strong className="text-slate-300">{rule.threshold}</strong></span>
                  <span className="text-purple-400">{rule.channel}</span>
                </div>
              </div>
            ))
          ) : (
            <div className="col-span-3 text-center text-xs text-slate-500 py-3 font-mono">
              Connecting to Transaction Fraud Rules Engine...
            </div>
          )}
        </div>
      </div>

      {/* 60-Second Guided Pitch Tour Modal */}
      {showDemoTour && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-fadeIn">
          <div className="glass-panel w-full max-w-2xl rounded-2xl border border-cyan-500/40 bg-slate-950 p-6 space-y-6 shadow-2xl relative">
            {/* Header */}
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center space-x-2.5">
                <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-slate-950 font-bold">
                  <Play className="w-4 h-4 fill-current" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-slate-100 uppercase tracking-tight">
                    60-Second Bank SOC Guided Pitch Tour
                  </h3>
                  <div className="text-[11px] font-mono text-cyan-400">
                    Smart India Hackathon (SIH) Live Demo Flow • 4 Controlled Stages
                  </div>
                </div>
              </div>
              <button
                onClick={() => setShowDemoTour(false)}
                className="text-slate-400 hover:text-slate-100 text-xs font-mono px-2 py-1 rounded bg-slate-900 border border-slate-800"
              >
                ✕ Close
              </button>
            </div>

            {/* Step Navigation Progress Bar */}
            <div className="grid grid-cols-4 gap-2">
              {[
                { step: 1, label: '1. Baseline & RBI' },
                { step: 2, label: '2. Adversary Attack' },
                { step: 3, label: '3. 6-Hr CERT-In' },
                { step: 4, label: '4. Containment' }
              ].map((s) => (
                <button
                  key={s.step}
                  onClick={() => setDemoTourStep(s.step as any)}
                  className={`py-2 px-1 text-center rounded-lg text-[10px] font-mono font-bold transition-all border ${
                    demoTourStep === s.step
                      ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/50'
                      : 'bg-slate-900/60 text-slate-500 border-slate-800 hover:text-slate-300'
                  }`}
                >
                  {s.label}
                </button>
              ))}
            </div>

            {/* Tour Feedback Message */}
            {demoFeedback && (
              <div className="p-3 rounded-xl bg-cyan-950/40 border border-cyan-500/40 text-cyan-300 text-xs font-mono">
                {demoFeedback}
              </div>
            )}

            {/* Step Content */}
            {demoTourStep === 1 && (
              <div className="space-y-4">
                <div className="space-y-1">
                  <h4 className="text-sm font-bold text-slate-100">Stage 1: Demo Bank Normal SOC Baseline</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Demonstrates how CyberGuard Grid continuously monitors 10 critical banking systems across 4 isolated network enclaves. The Cyber Risk Engine evaluates risk using a 10-factor weighted model and compares posture against 12 RBI CSITE controls.
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
                    <span className="text-slate-500 text-[10px] uppercase">Organization Identity</span>
                    <div className="text-slate-200 font-bold">Demo Bank (org-1)</div>
                    <div className="text-slate-400 text-[11px]">Scheduled Commercial Bank (BFSI)</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
                    <span className="text-slate-500 text-[10px] uppercase">Enclave Architecture</span>
                    <div className="text-emerald-400 font-bold">4 Microsegmented Zones</div>
                    <div className="text-slate-400 text-[11px]">CBS & HSM Enclave Air-Gapped</div>
                  </div>
                </div>

                <div className="pt-2 flex justify-end">
                  <button
                    onClick={() => setDemoTourStep(2)}
                    className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold font-mono transition-all"
                  >
                    Next: Adversary Attack Simulation →
                  </button>
                </div>
              </div>
            )}

            {demoTourStep === 2 && (
              <div className="space-y-4">
                <div className="space-y-1">
                  <h4 className="text-sm font-bold text-rose-400">Stage 2: Controlled Attack Injection (Live Threat Event)</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Simulate an adversary targeting Demo Bank's Payment Gateway with a high-velocity micro-debit burst (Scenario 3). Watch how the live bridge updates asset health, logs a critical security event, and increases the overall Cyber Risk score dynamically!
                  </p>
                </div>

                <div className="p-3.5 rounded-xl bg-rose-950/20 border border-rose-500/30 space-y-2 text-xs font-mono">
                  <div className="text-rose-400 font-bold flex items-center gap-1.5">
                    <Flame className="w-4 h-4" />
                    Target: UPI & Payment Gateway Processor (10.10.3.15)
                  </div>
                  <div className="text-slate-300">
                    Adversary vector: 420 micro-debits/min to suspect merchant VPA handles.
                  </div>
                  <div className="text-slate-400 text-[11px]">
                    Expected telemetry: Asset marks COMPROMISED, Risk score spikes +35 pts, rule RULE-TXN-01 triggers.
                  </div>
                </div>

                <div className="pt-2 flex items-center justify-between">
                  <button
                    onClick={() => setDemoTourStep(1)}
                    className="text-xs font-mono text-slate-400 hover:text-slate-200"
                  >
                    ← Back
                  </button>
                  <button
                    onClick={handleDemoAttackTrigger}
                    disabled={demoInjecting}
                    className="px-4 py-2 rounded-xl bg-rose-500 hover:bg-rose-400 text-slate-950 text-xs font-bold font-mono transition-all flex items-center space-x-1.5 disabled:opacity-50 shadow-lg"
                  >
                    <Zap className={`w-3.5 h-3.5 ${demoInjecting ? 'animate-spin' : ''}`} />
                    <span>{demoInjecting ? 'Injecting Attack...' : 'Simulate UPI Attack Now ⚡'}</span>
                  </button>
                </div>
              </div>
            )}

            {demoTourStep === 3 && (
              <div className="space-y-4">
                <div className="space-y-1">
                  <h4 className="text-sm font-bold text-amber-400">Stage 3: Statutory 6-Hour Incident Notification (CERT-In)</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Under Section 70B(6) of the IT Act and CERT-In Directions 2022, banks must formally dispatch incident advisories within 6 hours. CyberGuard Grid automatically formats and outputs the official Annexure 1 incident notice!
                  </p>
                </div>

                <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-cyan-400 font-bold">ANNEXURE 1 DISPATCH GENERATOR</span>
                    <span className="text-emerald-400">✓ 6-HOUR WINDOW MET</span>
                  </div>
                  <div className="text-slate-300">
                    Tracking No: <span className="text-slate-100">CERTIN-IN-2026-DEMOBANK-EVT-001</span>
                  </div>
                  <div className="text-slate-400 text-[11px]">
                    Includes technical IoCs, source IP ranges, ISO 8583 message switch impact, and CISO sign-off.
                  </div>
                </div>

                <div className="pt-2 flex items-center justify-between">
                  <button
                    onClick={() => navigate('/reports')}
                    className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-mono"
                  >
                    View Official Annexure 1 in Reports ↗
                  </button>
                  <button
                    onClick={() => setDemoTourStep(4)}
                    className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold font-mono transition-all"
                  >
                    Next: Automated Containment →
                  </button>
                </div>
              </div>
            )}

            {demoTourStep === 4 && (
              <div className="space-y-4">
                <div className="space-y-1">
                  <h4 className="text-sm font-bold text-emerald-400">Stage 4: Automated Countermeasure & Posture Restoration</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Deploy automated response playbook: Freeze compromised merchant endpoints, apply WAF velocity throttling, and log forensic signatures to the immutable cryptographic DLT Trust Ledger.
                  </p>
                </div>

                <div className="p-3.5 rounded-xl bg-emerald-950/20 border border-emerald-500/30 space-y-2 text-xs font-mono">
                  <div className="text-emerald-400 font-bold flex items-center gap-1.5">
                    <ShieldCheck className="w-4 h-4" />
                    Response Playbook: PB-UPI-CONTAINMENT-01
                  </div>
                  <div className="text-slate-300">
                    Actions: Throttle merchant endpoint, reset API sessions, verify Finacle CBS enclave integrity.
                  </div>
                  <div className="text-slate-400 text-[11px]">
                    Expected telemetry: Asset status returns to HEALTHY, Bank Cyber Risk drops by ~22 pts!
                  </div>
                </div>

                <div className="pt-2 flex items-center justify-between">
                  <button
                    onClick={() => setDemoTourStep(3)}
                    className="text-xs font-mono text-slate-400 hover:text-slate-200"
                  >
                    ← Back
                  </button>
                  <button
                    onClick={handleDemoRemediate}
                    disabled={demoRemediating}
                    className="px-4 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 text-xs font-bold font-mono transition-all flex items-center space-x-1.5 disabled:opacity-50 shadow-lg"
                  >
                    <CheckCircle className={`w-3.5 h-3.5 ${demoRemediating ? 'animate-spin' : ''}`} />
                    <span>{demoRemediating ? 'Restoring Defense...' : 'Deploy Countermeasure Now ✓'}</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Banking Asset Health Overview Strip (Core 7 Assets) */}
      <div className="bg-[#0F1420]/80 border border-cyan-500/20 p-5 rounded-2xl shadow-xl">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
          <div className="flex items-center gap-2">
            <Landmark className="w-5 h-5 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
              Banking Infrastructure Telemetry Overview
            </h3>
          </div>
          <button
            onClick={() => navigate('/bank-assets')}
            className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
          >
            Manage All 10 Assets <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
          {featuredAssets.map((asset) => (
            <div
              key={asset.id}
              onClick={() => navigate('/bank-assets')}
              className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 hover:border-cyan-500/50 cursor-pointer transition-all flex flex-col justify-between space-y-2.5"
            >
              <div className="flex items-center justify-between">
                {getAssetIcon(asset.category)}
                {getStatusBadge(asset.securityStatus)}
              </div>
              <div>
                <div className="text-xs font-bold text-slate-200 truncate" title={asset.name}>
                  {asset.name}
                </div>
                <div className="text-[10px] text-slate-400 font-mono truncate">{asset.ipOrIdentifier}</div>
              </div>
              <div className="pt-1.5 border-t border-slate-800 flex items-center justify-between text-[11px] font-mono">
                <span className="text-slate-400">Risk:</span>
                <span className={`font-bold ${
                  asset.riskScore >= 80 ? 'text-rose-400' :
                  asset.riskScore >= 65 ? 'text-amber-400' :
                  asset.riskScore >= 45 ? 'text-yellow-400' : 'text-emerald-400'
                }`}>
                  {asset.riskScore}/100
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Row 2: Cyber Risk Posture & Multi-Vector Radar */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Score Card with Circular HUD Gauge */}
        <div
          onClick={() => navigate('/cyber-risk')}
          className="glass-panel p-5 sm:p-6 rounded-2xl border border-rose-500/30 flex flex-col justify-between relative overflow-hidden bg-gradient-to-br from-rose-950/20 via-slate-900 to-slate-950 cursor-pointer hover:border-rose-500/80 transition-all group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider">BANK CYBER RISK SCORE</span>
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
                <circle cx="54" cy="54" r={gaugeRadius} stroke="#1e293b" strokeWidth="8" fill="transparent" />
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
              <div className="text-xs font-mono text-slate-200 font-bold">10-Factor Banking Algorithm</div>
              <div className="text-[11px] text-slate-400 leading-tight">
                CBS (15%), Payment GW (15%), Auth/HSM (15%), Endpoints (10%), ATM (10%), CIF (10%), Network (10%).
              </div>
              <div className="text-[10px] font-mono text-cyan-400 flex items-center space-x-1">
                <span>Weighted 100% Normalized</span>
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
              <TrendingUp className="w-3.5 h-3.5 mr-1 shrink-0" /> Click to view factor contributors
            </span>
            <span className="font-mono text-[11px] text-slate-500 hidden sm:inline">Dynamic Posture</span>
          </div>
        </div>

        {/* Banking Posture Radar Chart */}
        <div className="glass-panel p-5 sm:p-6 rounded-2xl border border-cyan-500/30 space-y-3 flex flex-col justify-between">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div className="flex items-center space-x-2">
              <ShieldCheck className="w-5 h-5 text-cyan-400" />
              <h3 className="text-xs font-bold text-slate-100 uppercase tracking-wider">BANKING RISK RADAR</h3>
            </div>
            <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 text-[10px] font-mono font-bold border border-cyan-800">
              8 Enclaves
            </span>
          </div>

          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={radarData}>
                <PolarGrid stroke="#334155" strokeDasharray="3 3" />
                <PolarAngleAxis dataKey="category" tick={{ fill: '#94a3b8', fontSize: 9, fontFamily: 'monospace' }} />
                <PolarRadiusAxis angle={30} domain={[0, 100]} stroke="#475569" tick={{ fill: '#64748b', fontSize: 8 }} />
                <Radar name="Defensive Resilience" dataKey="defense" stroke="#06b6d4" fill="#06b6d4" fillOpacity={0.35} strokeWidth={2} />
                <Radar name="Risk Exposure" dataKey="risk" stroke="#f43f5e" fill="#f43f5e" fillOpacity={0.2} strokeWidth={1.5} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '0.75rem', fontSize: '11px', fontFamily: 'monospace' }}
                  itemStyle={{ color: '#f8fafc' }}
                />
              </RadarChart>
            </ResponsiveContainer>
          </div>

          <div className="flex items-center justify-around pt-2 border-t border-slate-800/80 text-[10px] font-mono">
            <div className="flex items-center space-x-1.5">
              <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
              <span className="text-slate-300">Resilience: {Math.max(0, 100 - currentRiskScore)}%</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className="w-2 h-2 rounded-full bg-rose-500"></span>
              <span className="text-slate-300">Exposure: {currentRiskScore}%</span>
            </div>
          </div>
        </div>

        {/* Vulnerabilities by Banking Asset Bar Chart */}
        <div className="glass-panel p-5 sm:p-6 rounded-2xl border border-slate-800/80 space-y-3 flex flex-col justify-between">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="w-5 h-5 text-amber-400" />
              <h3 className="text-xs font-bold text-slate-100 uppercase tracking-wider">VULNERABILITIES BY ASSET</h3>
            </div>
            <span className="px-2 py-0.5 rounded bg-slate-900 text-slate-300 text-[10px] font-mono border border-slate-700">
              CVE Telemetry
            </span>
          </div>

          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={assetVulnChartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="name" stroke="#64748b" tick={{ fontSize: 9, fontFamily: 'monospace' }} />
                <YAxis stroke="#64748b" tick={{ fontSize: 9, fontFamily: 'monospace' }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '0.75rem', fontSize: '11px', fontFamily: 'monospace' }}
                  itemStyle={{ color: '#f8fafc' }}
                />
                <Bar dataKey="vulns" name="Known CVEs" fill="#f59e0b" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="pt-2 border-t border-slate-800/80 text-[10px] font-mono text-slate-400 flex items-center justify-between">
            <span>Payment Gateway & NetBanking hold most CVEs</span>
            <button onClick={() => navigate('/threat-intelligence')} className="text-cyan-400 hover:underline">
              Vulnerability Hub →
            </button>
          </div>
        </div>
      </div>

      {/* Row 3: Live Banking Security Events Feed & Remediation Playbook */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Live Security Events Table (2 cols) */}
        <div className="lg:col-span-2 glass-panel p-5 sm:p-6 rounded-2xl border border-slate-800/80 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center space-x-2">
              <Radio className="w-5 h-5 text-rose-400 animate-pulse" />
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
                RECENT BANK SECURITY EVENTS
              </h3>
            </div>
            <button
              onClick={() => navigate('/threat-detection')}
              className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
            >
              Threat Detection Stream →
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/60 text-slate-400 uppercase font-mono">
                  <th className="py-2.5 px-3">Event ID</th>
                  <th className="py-2.5 px-3">Category</th>
                  <th className="py-2.5 px-3">Affected Asset</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3 text-right">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {securityEvents.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-6 text-center text-slate-500 font-mono">
                      No recent security alerts recorded.
                    </td>
                  </tr>
                ) : (
                  securityEvents.map((evt) => (
                    <tr key={evt.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-2.5 px-3 font-mono font-bold text-cyan-400">{evt.id}</td>
                      <td className="py-2.5 px-3 text-slate-200 font-medium">{evt.eventCategory}</td>
                      <td className="py-2.5 px-3 text-slate-300 truncate max-w-[140px]">{evt.affectedAssetName || evt.affectedAssetId}</td>
                      <td className="py-2.5 px-3">{getSeverityBadge(evt.severity)}</td>
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                          evt.investigationStatus === 'NEW' ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20' :
                          evt.investigationStatus === 'INVESTIGATING' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                          evt.investigationStatus === 'CONTAINED' ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20' :
                          'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                        }`}>
                          {evt.investigationStatus}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right font-mono text-slate-500 whitespace-nowrap">
                        {new Date(evt.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Top Priority Remediation Playbook (1 col) */}
        <div className="glass-panel p-5 sm:p-6 rounded-2xl border border-amber-500/30 space-y-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Zap className="w-5 h-5 text-amber-400" />
                <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">REMEDIATION ACTIONS</h3>
              </div>
              <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-400 text-xs font-mono font-bold border border-rose-800">
                Playbook
              </span>
            </div>

            <div className="mt-3">
              <h4 className="text-sm font-bold text-slate-200">Demo Bank SOC Remediation Queue</h4>
              <p className="text-[11px] text-slate-400 mt-1">
                Execute prioritized mitigations to suppress attack vectors and dynamically lower bank risk score.
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
            {displayActions.map((act, i) => {
              const isDone = act.status === 'Completed';
              return (
                <div
                  key={act.id}
                  onClick={() => !isDone && handleTopActionClick(i)}
                  className={`flex items-center justify-between p-2.5 rounded-lg border text-xs transition-all ${
                    isDone
                      ? 'bg-slate-950/60 border-emerald-900/60 opacity-85'
                      : 'bg-slate-900 hover:bg-slate-800 border-slate-800 hover:border-cyan-500/60 cursor-pointer'
                  }`}
                >
                  <div className="flex items-center space-x-2 flex-1 pr-2">
                    <Zap className={`w-3.5 h-3.5 shrink-0 ${isDone ? 'text-emerald-400' : 'text-cyan-400'}`} />
                    <span className={isDone ? 'text-slate-400 line-through truncate' : 'text-slate-200 font-medium truncate'}>
                      {act.title}
                    </span>
                  </div>

                  {isDone ? (
                    <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 font-mono text-[9px] font-bold border border-emerald-800 flex items-center space-x-1 shrink-0">
                      <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                      <span>✓ Executed (-{act.estimatedRiskReduction} pts)</span>
                    </span>
                  ) : (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleTopActionClick(i);
                      }}
                      disabled={executingIdx === i}
                      className="px-2.5 py-1 rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-mono text-[10px] font-bold shadow glow-cyan shrink-0 flex items-center space-x-1 transition-all"
                    >
                      <Play className={`w-2.5 h-2.5 fill-slate-950 ${executingIdx === i ? 'animate-spin' : ''}`} />
                      <span>{executingIdx === i ? 'Executing...' : 'Execute'}</span>
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
