import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Play,
  Pause,
  SkipBack,
  SkipForward,
  RotateCcw,
  X,
  Sparkles,
  ShieldAlert,
  ShieldCheck,
  ChevronRight,
  RefreshCw,
  Calendar,
  AlertTriangle,
  Radio,
  Lock,
  ArrowRight
} from 'lucide-react';
import { useApp, DEMO_STEPS } from '../../context/AppContext';

export const DemoModeController: React.FC = () => {
  const {
    isDemoActive,
    demoStep,
    isDemoAutoPlaying,
    startDemo,
    stopDemo,
    setDemoStep,
    nextDemoStep,
    prevDemoStep,
    toggleDemoAutoPlay,
    resetDemoBaseline
  } = useApp();

  const [isResetting, setIsResetting] = useState(false);
  const navigate = useNavigate();
  const currentStep = DEMO_STEPS.find((s) => s.stepNumber === demoStep) || DEMO_STEPS[0];

  // Automatically switch page on demo step change
  useEffect(() => {
    if (isDemoActive && currentStep?.targetPage) {
      navigate(currentStep.targetPage);
    }
  }, [demoStep, isDemoActive]);

  const handleResetBaseline = async () => {
    setIsResetting(true);
    try {
      await resetDemoBaseline();
    } finally {
      setIsResetting(false);
    }
  };

  if (!isDemoActive) return null;

  return (
    <>
      {/* Day 4 Completion Overlay Modal */}
      {demoStep === 4 && !isDemoAutoPlaying && (
        <div className="fixed inset-0 z-40 bg-slate-950/80 backdrop-blur-md flex items-center justify-center p-6 animate-fadeIn">
          <div className="max-w-xl w-full bg-slate-900 border border-emerald-500/50 rounded-3xl p-6 sm:p-8 shadow-2xl shadow-emerald-950/70 text-center space-y-5">
            <div className="inline-flex items-center justify-center p-3.5 rounded-2xl bg-emerald-950/80 border border-emerald-500/40 text-emerald-400">
              <ShieldCheck className="w-10 h-10 animate-pulse" />
            </div>

            <div>
              <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-700">
                4-DAY DEFENSE NARRATIVE COMPLETED
              </span>
              <h2 className="text-2xl font-black text-slate-100 tracking-tight mt-2">
                ATTACK NEUTRALIZED & CONTAINED
              </h2>
              <p className="text-xs text-slate-400 mt-1.5 font-mono">
                From infiltration detection to cross-organization early warning and cryptographic verification.
              </p>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono text-left">
              <div className="p-3 rounded-xl bg-slate-950/90 border border-slate-800">
                <div className="text-[10px] text-slate-500">Day 1 Posture</div>
                <div className="text-emerald-400 font-bold mt-0.5">42 Baseline</div>
              </div>
              <div className="p-3 rounded-xl bg-slate-950/90 border border-slate-800">
                <div className="text-[10px] text-slate-500">Day 2 Infiltration</div>
                <div className="text-amber-400 font-bold mt-0.5">78 Rising</div>
              </div>
              <div className="p-3 rounded-xl bg-slate-950/90 border border-slate-800">
                <div className="text-[10px] text-slate-500">Day 3 Warning</div>
                <div className="text-rose-400 font-bold mt-0.5">91 Critical</div>
              </div>
              <div className="p-3 rounded-xl bg-slate-950/90 border border-slate-800">
                <div className="text-[10px] text-slate-500">Day 4 Outcome</div>
                <div className="text-emerald-400 font-bold mt-0.5">24 Remediated</div>
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 space-y-1 text-left">
              <div className="flex items-center space-x-2 text-emerald-400 font-bold">
                <span>✓</span>
                <span>Threat Pattern TH-7821 committed to DLT Ledger (Block #10421)</span>
              </div>
              <div className="flex items-center space-x-2 text-emerald-400 font-bold">
                <span>✓</span>
                <span>Zero PII leaked: Behavioral sequence sanitized via Differential Privacy</span>
              </div>
              <div className="flex items-center space-x-2 text-emerald-400 font-bold">
                <span>✓</span>
                <span>P2P early warning gossip successfully received by City Hospital & FinTech Corp</span>
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
              <button
                onClick={startDemo}
                className="px-5 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs transition border border-slate-700 flex items-center space-x-1.5"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Replay 4-Day Demo</span>
              </button>
              <button
                onClick={handleResetBaseline}
                disabled={isResetting}
                className="px-5 py-2.5 rounded-xl bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-700 text-cyan-300 font-bold text-xs flex items-center space-x-1.5"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isResetting ? 'animate-spin' : ''}`} />
                <span>Reset to Clean Baseline</span>
              </button>
              <button
                onClick={stopDemo}
                className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-600 text-slate-950 font-bold text-xs shadow-lg hover:from-emerald-400 hover:to-cyan-500 transition"
              >
                Exit Demo Mode
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Floating 4-Day Automated Demo Controller Overlay Bar */}
      <div className="fixed bottom-2 sm:bottom-6 left-1/2 -translate-x-1/2 z-50 w-[calc(100vw-1rem)] sm:w-full max-w-4xl px-1 sm:px-4 animate-bounce-short">
        <div className="glass-panel-glow bg-[#0F1420]/95 backdrop-blur-xl border border-cyan-500/50 rounded-2xl p-3 sm:p-4 shadow-2xl shadow-cyan-950/90 text-slate-100 space-y-3">
          {/* Day Stepper Tabs */}
          <div className="flex items-center justify-between gap-2 border-b border-slate-800 pb-2.5">
            <div className="flex items-center space-x-1 sm:space-x-2 overflow-x-auto">
              {DEMO_STEPS.map((s) => {
                const isCurrent = demoStep === s.stepNumber;
                return (
                  <button
                    key={s.stepNumber}
                    onClick={() => setDemoStep(s.stepNumber)}
                    className={`px-2.5 sm:px-3 py-1 rounded-lg text-[10px] sm:text-xs font-mono font-bold transition-all flex items-center space-x-1 whitespace-nowrap ${
                      isCurrent
                        ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 shadow-md ring-1 ring-cyan-400'
                        : 'bg-slate-900/90 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800'
                    }`}
                  >
                    <Calendar className="w-3 h-3 shrink-0" />
                    <span>Day {s.stepNumber}</span>
                  </button>
                );
              })}
            </div>

            {/* Playback Controls & Reset */}
            <div className="flex items-center space-x-1.5 sm:space-x-2 shrink-0">
              <button
                onClick={prevDemoStep}
                disabled={demoStep <= 1}
                className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-300 disabled:opacity-30 disabled:cursor-not-allowed"
                title="Previous Day"
              >
                <SkipBack className="w-3.5 h-3.5" />
              </button>

              <button
                onClick={toggleDemoAutoPlay}
                className="px-2.5 sm:px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center space-x-1 transition-all"
                title={isDemoAutoPlaying ? 'Pause Day Playback' : 'Auto-Play Narrative'}
              >
                {isDemoAutoPlaying ? (
                  <>
                    <Pause className="w-3.5 h-3.5" />
                    <span className="hidden sm:inline">Pause</span>
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5" />
                    <span className="hidden sm:inline">Auto-Play</span>
                  </>
                )}
              </button>

              <button
                onClick={nextDemoStep}
                disabled={demoStep >= DEMO_STEPS.length}
                className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-300 disabled:opacity-30 disabled:cursor-not-allowed"
                title="Next Day"
              >
                <SkipForward className="w-3.5 h-3.5" />
              </button>

              <button
                onClick={handleResetBaseline}
                disabled={isResetting}
                className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:bg-amber-950 hover:text-amber-300 text-slate-400 transition-colors"
                title="Reset Demo Baseline"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isResetting ? 'animate-spin' : ''}`} />
              </button>

              <button
                onClick={stopDemo}
                className="p-1.5 rounded-lg bg-rose-950/60 border border-rose-800 hover:bg-rose-900 text-rose-300"
                title="Exit Demo"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Active Day Detail Banner */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 items-center">
            <div className="md:col-span-2 space-y-1">
              <div className="flex items-center space-x-2">
                <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase bg-cyan-950 text-cyan-300 border border-cyan-800">
                  {currentStep.badge}
                </span>
                <span className="text-xs font-bold text-slate-100 truncate">{currentStep.title}</span>
              </div>
              <p className="text-[11px] font-semibold text-cyan-400">{currentStep.subtitle}</p>
              <p className="text-[10px] text-slate-400 leading-relaxed">{currentStep.explanation}</p>
            </div>

            <div className="flex flex-col justify-between h-full bg-slate-900/90 rounded-xl p-2.5 border border-slate-800 font-mono text-xs space-y-2">
              <div className="flex items-center justify-between text-[10px]">
                <span className="text-slate-400">Target Visualizer:</span>
                <span className="text-cyan-400 font-bold">{currentStep.targetPage}</span>
              </div>

              <div className="flex items-center justify-between text-[10px]">
                <span className="text-slate-400">Day State:</span>
                <span className={`font-bold ${
                  demoStep === 1
                    ? 'text-emerald-400'
                    : demoStep === 2
                    ? 'text-amber-400'
                    : demoStep === 3
                    ? 'text-rose-400'
                    : 'text-emerald-400'
                }`}>
                  {demoStep === 1
                    ? 'Risk 42 (Baseline)'
                    : demoStep === 2
                    ? 'Risk 78 (Infiltration)'
                    : demoStep === 3
                    ? 'Risk 91 (Critical)'
                    : 'Risk 24 (Remediated)'}
                </span>
              </div>

              <button
                onClick={nextDemoStep}
                disabled={demoStep >= DEMO_STEPS.length}
                className="w-full py-1.5 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 font-bold text-[11px] flex items-center justify-center space-x-1 disabled:opacity-40"
              >
                <span>{demoStep < DEMO_STEPS.length ? `Advance to Day ${demoStep + 1}` : 'Narrative Complete'}</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Progress bar showing progress across the 4 days */}
          <div className="space-y-1">
            <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden border border-slate-800">
              <div
                className="bg-gradient-to-r from-emerald-500 via-amber-500 to-cyan-500 h-full transition-all duration-500"
                style={{ width: `${(demoStep / DEMO_STEPS.length) * 100}%` }}
              />
            </div>
            <div className="flex items-center justify-between text-[9px] font-mono text-slate-500">
              <span>Day 1 • Baseline (42)</span>
              <span>Day 2 • Lateral Attack (78)</span>
              <span>Day 3 • Mesh Early Warning (91)</span>
              <span>Day 4 • Containment (24)</span>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};
