import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Crosshair,
  Play,
  Pause,
  SkipBack,
  SkipForward,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  Zap,
  ArrowRight,
  Shield,
  Radio,
  Sparkles,
  Plus,
  ArrowUpRight,
  ShieldCheck,
  Info,
  TrendingDown,
  Scissors
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import { AttackScenario } from '../types';

export const AttackSimulator: React.FC = () => {
  const { attackScenarios, simulateAttack, remediateWeakPoint, activeOrg } = useApp();
  const navigate = useNavigate();
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>('scenario-1');
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [isPlayingSteps, setIsPlayingSteps] = useState<boolean>(false);
  const [activeStepIndex, setActiveStepIndex] = useState<number>(-1);
  const [isRemediating, setIsRemediating] = useState<boolean>(false);
  const [remediationSuccess, setRemediationSuccess] = useState<any>(null);
  const [whatIfFix, setWhatIfFix] = useState<boolean>(false);

  const fallbackScenario: AttackScenario = {
    id: 'scenario-1',
    name: 'Phishing to Privilege Escalation & Lateral Movement',
    probability: 88,
    impact: 'CRITICAL',
    scenarioRisk: 91,
    criticalWeakPoint: 'Identity Provider (Lack of FIDO2 Hardware Key Enforcement)',
    description: 'Adversary uses spear phishing email to harvest credentials, exploits lack of hardware MFA, elevates privileges to Domain Admin, and exfiltrates sensitive database assets.',
    explanation: 'Legacy SMS OTP authentication allows credential interception. Enforcing WebAuthn hardware keys severs this attack chain.',
    nodes: [
      {
        id: 'node-1',
        name: 'Initial Access (Phishing)',
        stage: 'Initial Entry',
        risk: 15,
        probability: 90,
        impact: 'MEDIUM',
        exploitability: 'High',
        reason: 'Phishing email bypasses perimeter filters.',
        affectedAsset: 'Corporate Mailbox',
        recommendedControl: 'Email Threat Protection'
      },
      {
        id: 'node-2',
        name: 'Credential Access (Lack of FIDO2)',
        stage: 'Authentication Bypass',
        risk: 35,
        probability: 85,
        impact: 'CRITICAL',
        exploitability: 'Critical',
        reason: 'SMS OTP intercepted due to lack of hardware keys.',
        affectedAsset: 'Identity Provider (Okta / Azure AD)',
        recommendedControl: 'Enforce FIDO2 Hardware Keys'
      },
      {
        id: 'node-3',
        name: 'Privilege Escalation',
        stage: 'Lateral Movement',
        risk: 25,
        probability: 78,
        impact: 'HIGH',
        exploitability: 'High',
        reason: 'Service account privileges elevated to Domain Super Admin.',
        affectedAsset: 'Domain Controller',
        recommendedControl: 'Privileged Access Management (PAM)'
      },
      {
        id: 'node-4',
        name: 'Data Exfiltration',
        stage: 'Impact',
        risk: 16,
        probability: 70,
        impact: 'CRITICAL',
        exploitability: 'Critical',
        reason: 'Unauthorized bulk transfer to external endpoint.',
        affectedAsset: 'Customer Oracle Production DB',
        recommendedControl: 'Data Loss Prevention (DLP)'
      }
    ]
  };

  const scenario: AttackScenario = (attackScenarios && attackScenarios.length > 0)
    ? (attackScenarios.find((s) => s.id === selectedScenarioId) || attackScenarios[0])
    : fallbackScenario;

  const nodes = scenario?.nodes || fallbackScenario.nodes;

  // Automated step-by-step playback timer
  useEffect(() => {
    let timer: any = null;
    if (isPlayingSteps) {
      timer = setInterval(() => {
        setActiveStepIndex((prev) => {
          if (prev >= nodes.length - 1) {
            setIsPlayingSteps(false);
            return prev;
          }
          return prev + 1;
        });
      }, 900);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [isPlayingSteps, nodes.length]);

  const handleRunSimulation = async () => {
    setIsSimulating(true);
    setRemediationSuccess(null);
    setActiveStepIndex(0);

    for (let i = 0; i < nodes.length; i++) {
      await new Promise((res) => setTimeout(res, 400));
      setActiveStepIndex(i);
    }

    if (scenario?.id) {
      await simulateAttack(scenario.id);
    }
    setIsSimulating(false);
  };

  const handleRemediateClick = async () => {
    setIsRemediating(true);
    const res = await remediateWeakPoint();
    setIsRemediating(false);
    if (res.success) {
      setRemediationSuccess(res);
      setWhatIfFix(false);
    }
  };

  const handleStepNext = () => {
    if (activeStepIndex < nodes.length - 1) {
      setActiveStepIndex(activeStepIndex + 1);
    }
  };

  const handleStepPrev = () => {
    if (activeStepIndex > 0) {
      setActiveStepIndex(activeStepIndex - 1);
    }
  };

  const handleResetSteps = () => {
    setIsPlayingSteps(false);
    setActiveStepIndex(-1);
  };

  // Find index of the node with highest risk contribution (the weakest link)
  const maxRiskNodeIndex = nodes.reduce(
    (maxIdx, node, idx, arr) => (node.risk > arr[maxIdx].risk ? idx : maxIdx),
    0
  );

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 sm:space-y-8 max-w-7xl mx-auto">
      {/* Prominent Visible Simulation Notice */}
      <div className="p-3.5 rounded-2xl bg-amber-950/40 border border-amber-800/80 text-amber-300 font-mono text-xs flex items-center justify-between gap-3 shadow-md">
        <div className="flex items-center space-x-2.5">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 animate-pulse" />
          <span>
            <strong>Simulation only. No real attack is performed.</strong> All adversary tactics, execution traces, and telemetry are safely modelled.
          </span>
        </div>
        <span className="hidden md:inline px-2 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-800 text-[10px] font-bold">
          SAFE SANDBOX
        </span>
      </div>

      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-100 uppercase">SAFE ATTACK SIMULATOR</h1>
            <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-400 text-[10px] font-mono border border-rose-800 font-bold">
              TTP EMULATOR
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Simulate adversary tactics, techniques, and procedures (TTPs) using deterministic mock attack progressions.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 sm:gap-3 w-full sm:w-auto">
          {/* Counterfactual "What if I fix this?" Toggle */}
          <button
            onClick={() => setWhatIfFix(!whatIfFix)}
            className={`flex items-center space-x-2 px-3.5 py-2.5 rounded-xl border text-xs font-mono font-bold transition-all ${
              whatIfFix
                ? 'bg-emerald-950 text-emerald-300 border-emerald-500 ring-2 ring-emerald-500/40 shadow-lg shadow-emerald-950/50'
                : 'bg-slate-900 text-slate-300 border-slate-800 hover:border-slate-700'
            }`}
          >
            <Sparkles className={`w-3.5 h-3.5 ${whatIfFix ? 'text-emerald-400 animate-spin' : 'text-slate-400'}`} />
            <span>{whatIfFix ? 'WHAT-IF ACTIVE (-24 PTS)' : 'WHAT IF I FIX THIS?'}</span>
          </button>

          <button
            onClick={handleRunSimulation}
            disabled={isSimulating}
            className="flex-1 sm:flex-initial flex items-center justify-center space-x-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-rose-500 via-red-600 to-amber-600 text-slate-950 font-black text-xs transition-all shadow-lg shadow-rose-500/20 glow-red hover:opacity-90 disabled:opacity-50"
          >
            <Play className={`w-4 h-4 fill-slate-950 shrink-0 ${isSimulating ? 'animate-spin' : ''}`} />
            <span>{isSimulating ? 'SIMULATING PROGRESSION...' : 'RUN FULL SIMULATION'}</span>
          </button>
        </div>
      </div>

      {/* What-If Counterfactual Projected Banner */}
      {whatIfFix && !remediationSuccess && (
        <div className="p-4 rounded-xl bg-emerald-950/70 border-2 border-emerald-500 text-emerald-200 text-xs font-mono flex flex-col md:flex-row md:items-center justify-between gap-3 animate-fadeIn shadow-lg shadow-emerald-950/50">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-emerald-900/60 text-emerald-300 shrink-0">
              <Scissors className="w-5 h-5 text-emerald-400" />
            </div>
            <div>
              <div className="font-bold text-sm text-emerald-300 uppercase tracking-wide">
                COUNTERFACTUAL WHAT-IF ANALYSIS (PROJECTED OUTCOME)
              </div>
              <p className="text-slate-300 text-xs mt-0.5">
                Severing weakest link <strong className="text-emerald-300">"{scenario.criticalWeakPoint}"</strong> immediately prevents lateral movement.
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-3 shrink-0">
            <div className="px-3 py-1.5 rounded-lg bg-slate-950/90 border border-emerald-800 text-right">
              <span className="text-[10px] text-slate-400">Projected Risk: </span>
              <strong className="text-emerald-400 text-sm">
                {activeOrg?.riskScore ?? 84} → {Math.max(20, (activeOrg?.riskScore ?? 84) - 24)} (-24 pts)
              </strong>
            </div>

            <button
              onClick={handleRemediateClick}
              disabled={isRemediating}
              className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs flex items-center space-x-1.5"
            >
              <Zap className="w-3.5 h-3.5 fill-slate-950" />
              <span>Apply Fix Permanently</span>
            </button>
          </div>
        </div>
      )}

      {/* Remediation Success Banner */}
      {remediationSuccess && (
        <div className="p-4 rounded-xl bg-emerald-950/80 border border-emerald-500/80 text-emerald-200 text-xs font-mono font-bold flex items-center justify-between animate-fadeIn">
          <div className="flex items-center space-x-3">
            <ShieldCheck className="w-6 h-6 text-emerald-400 shrink-0" />
            <div>
              <div className="text-sm font-bold text-emerald-300">✓ CRITICAL WEAKNESS SUCCESSFULLY REMEDIATED!</div>
              <div className="text-[11px] text-slate-300 mt-0.5">
                {remediationSuccess.remediatedControl}. Risk score dropped from {remediationSuccess.previousScore} to {remediationSuccess.newScore} (-{remediationSuccess.reduction} pts).
              </div>
            </div>
          </div>
          <button onClick={() => navigate('/response-center')} className="px-3 py-1.5 rounded bg-emerald-500 text-slate-950 font-bold text-xs hover:bg-emerald-400">
            View Response Playbook
          </button>
        </div>
      )}

      {/* Scenario Selector Tabs */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
        {attackScenarios.map((s) => (
          <button
            key={s.id}
            onClick={() => {
              setSelectedScenarioId(s.id);
              setActiveStepIndex(-1);
              setIsPlayingSteps(false);
              setRemediationSuccess(null);
            }}
            className={`p-3 rounded-xl text-left border text-xs font-medium transition-all ${
              selectedScenarioId === s.id
                ? 'bg-gradient-to-br from-rose-950/60 to-slate-900 border-rose-500/80 text-rose-300 shadow-md'
                : 'bg-slate-900/80 border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
            }`}
          >
            <div className="text-[10px] font-mono text-slate-500 uppercase truncate">Scenario</div>
            <div className="font-bold truncate mt-1">{s.name}</div>
          </button>
        ))}
      </div>

      {/* Main Simulation Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Scenario Overview Metrics */}
        <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-6">
          <div>
            <div className="text-[10px] font-mono text-cyan-400 uppercase tracking-wider">Active Attack Vector</div>
            <h3 className="text-lg font-bold text-slate-100 mt-1">{scenario.name}</h3>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">{scenario.description}</p>
          </div>

          <div className="grid grid-cols-3 gap-2 sm:gap-3">
            <div className="p-2 sm:p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-center min-w-0">
              <div className="text-[10px] font-mono text-slate-500 uppercase truncate">Probability</div>
              <div className="text-sm sm:text-base lg:text-lg font-bold font-mono text-amber-400 mt-1 truncate">{scenario.probability}%</div>
            </div>
            <div className="p-2 sm:p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-center min-w-0">
              <div className="text-[10px] font-mono text-slate-500 uppercase truncate">Impact</div>
              <div className="text-xs sm:text-sm lg:text-base font-bold font-mono text-rose-400 mt-1 truncate tracking-tight">{scenario.impact}</div>
            </div>
            <div className="p-2 sm:p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-center min-w-0">
              <div className="text-[10px] font-mono text-slate-500 uppercase truncate">Scenario Risk</div>
              <div className="text-xs sm:text-sm lg:text-base font-bold font-mono text-rose-400 mt-1 truncate">{scenario.scenarioRisk}/100</div>
            </div>
          </div>

          {/* Identified Critical Weak Point & GREEN REMEDIATE BUTTON */}
          <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/80 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2 text-rose-400 font-bold text-xs">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span className="uppercase">CRITICAL WEAK POINT</span>
              </div>
              <span className="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-700 animate-pulse">
                <span className="w-2 h-2 rounded-full bg-rose-400"></span>
                <span>WEAKEST LINK</span>
              </span>
            </div>
            <div className="text-sm font-bold text-slate-100">{scenario.criticalWeakPoint}</div>
            <p className="text-xs text-slate-300 leading-relaxed">{scenario.explanation}</p>

            {/* GREEN REMEDIATION BUTTON */}
            {remediationSuccess ? (
              <div className="w-full py-2.5 rounded-xl bg-emerald-950 border border-emerald-500 text-emerald-400 font-bold text-xs font-mono flex items-center justify-center space-x-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span>✓ WEAK POINT REMEDIATED (SCORE NORMALIZED)</span>
              </div>
            ) : (
              <button
                onClick={handleRemediateClick}
                disabled={isRemediating}
                className="w-full py-3 rounded-xl bg-emerald-500 hover:bg-emerald-400 active:bg-emerald-600 text-slate-950 font-extrabold text-xs flex items-center justify-center space-x-2 shadow-lg shadow-emerald-500/25 transition-all transform hover:scale-[1.02] cursor-pointer"
              >
                <Zap className={`w-4 h-4 fill-slate-950 ${isRemediating ? 'animate-spin' : ''}`} />
                <span>{isRemediating ? 'REMEDIATING WEAK POINT...' : 'REMEDIATE WEAK POINT NOW (-24 PTS RISK)'}</span>
              </button>
            )}
          </div>
        </div>

        {/* Right: Step-by-Step Simulated Progression with Playback Controls */}
        <div className="lg:col-span-2 glass-panel p-6 rounded-2xl border border-slate-800 space-y-5">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
            <div>
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
                <Sparkles className="w-4 h-4 text-cyan-400" />
                <span>STEP-BY-STEP ADVERSARY PROGRESSION</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Playback the lateral attack sequence node-by-node or step manually through TTPs.
              </p>
            </div>

            {/* Step Playback Controls */}
            <div className="flex items-center space-x-1.5 font-mono text-xs">
              <button
                onClick={handleStepPrev}
                disabled={activeStepIndex <= 0}
                className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-300 disabled:opacity-30 disabled:cursor-not-allowed"
                title="Step Backward"
              >
                <SkipBack className="w-3.5 h-3.5" />
              </button>

              <button
                onClick={() => setIsPlayingSteps(!isPlayingSteps)}
                className="px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center space-x-1"
                title={isPlayingSteps ? 'Pause Step Playback' : 'Play Step-by-Step'}
              >
                {isPlayingSteps ? (
                  <>
                    <Pause className="w-3.5 h-3.5" />
                    <span>Pause</span>
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5" />
                    <span>Play</span>
                  </>
                )}
              </button>

              <button
                onClick={handleStepNext}
                disabled={activeStepIndex >= nodes.length - 1}
                className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-300 disabled:opacity-30 disabled:cursor-not-allowed"
                title="Step Forward"
              >
                <SkipForward className="w-3.5 h-3.5" />
              </button>

              <button
                onClick={handleResetSteps}
                className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-400"
                title="Reset Steps"
              >
                <RotateCcw className="w-3.5 h-3.5" />
              </button>

              <button
                onClick={() => navigate('/attack-path')}
                className="text-xs font-mono text-cyan-400 hover:underline flex items-center space-x-1 ml-2"
              >
                <span>DAG Map</span>
                <ArrowUpRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          <div className="space-y-4">
            {nodes.map((node, idx) => {
              const isActive = activeStepIndex >= idx;
              const isWeakestLink = idx === maxRiskNodeIndex;
              const isSeveredByWhatIf = whatIfFix && isWeakestLink;

              return (
                <div
                  key={node.id}
                  className={`p-4 rounded-xl border transition-all duration-300 flex items-start space-x-4 relative overflow-hidden ${
                    isSeveredByWhatIf
                      ? 'bg-emerald-950/30 border-2 border-dashed border-emerald-500 ring-2 ring-emerald-500/20'
                      : isWeakestLink
                      ? 'bg-rose-950/25 border-rose-600/90 shadow-md shadow-rose-950/60'
                      : isActive
                      ? 'bg-slate-900/90 border-cyan-500/80 shadow-lg shadow-cyan-950/50'
                      : 'bg-slate-950/40 border-slate-800/80 opacity-60'
                  }`}
                >
                  <div
                    className={`w-8 h-8 rounded-full flex items-center justify-center font-mono font-bold text-xs shrink-0 ${
                      isSeveredByWhatIf
                        ? 'bg-emerald-500 text-slate-950'
                        : isWeakestLink
                        ? 'bg-rose-500 text-slate-950 animate-pulse'
                        : isActive
                        ? 'bg-cyan-500 text-slate-950'
                        : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {idx + 1}
                  </div>

                  <div className="flex-1 space-y-1">
                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <div className="flex items-center space-x-2">
                        <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-wider font-bold">
                          STAGE {idx + 1}: {node.stage}
                        </span>
                        {isWeakestLink && (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-[9px] font-bold font-mono bg-rose-950 text-rose-300 border border-rose-700 animate-pulse">
                            ⚡ WEAKEST LINK (CHOKEPOINT)
                          </span>
                        )}
                        {isSeveredByWhatIf && (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-[9px] font-bold font-mono bg-emerald-950 text-emerald-300 border border-emerald-700">
                            ✓ SEVERED VIA COUNTERFACTUAL
                          </span>
                        )}
                      </div>

                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800">
                        Risk Contribution: +{node.risk}
                      </span>
                    </div>

                    <h4 className="text-sm font-bold text-slate-100">{node.name}</h4>
                    <p className="text-xs text-slate-400">{node.reason}</p>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-2 text-[11px] font-mono">
                      <div className="bg-slate-950 p-2 rounded border border-slate-800 text-slate-300 truncate">
                        <strong className="text-slate-400">Target Asset:</strong> {node.affectedAsset}
                      </div>
                      <div className="bg-slate-950 p-2 rounded border border-slate-800 text-cyan-400 truncate">
                        <strong className="text-slate-400">Control Needed:</strong> {node.recommendedControl}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
