import React, { useState, useEffect } from 'react';
import {
  Radio,
  Plus,
  AlertTriangle,
  CheckCircle2,
  ShieldAlert,
  Zap,
  Activity,
  ArrowRight,
  Play,
  Pause
} from 'lucide-react';
import { useApp } from '../context/AppContext';

export const ThreatDetection: React.FC = () => {
  const { telemetryStream, injectTelemetryEvent, riskData } = useApp();
  const [selectedEventType, setSelectedEventType] = useState<string>('PRIVILEGE_ESCALATION');
  const [customDetails, setCustomDetails] = useState<string>('');
  const [isInjecting, setIsInjecting] = useState(false);
  const [isAutoStreaming, setIsAutoStreaming] = useState(false);

  const handleInjectTelemetry = async () => {
    setIsInjecting(true);
    await injectTelemetryEvent(
      selectedEventType,
      customDetails || `${selectedEventType} event ingested via Threat Detection Command Center.`
    );
    setCustomDetails('');
    setIsInjecting(false);
  };

  useEffect(() => {
    let timer: any = null;
    let stepIndex = 0;
    if (isAutoStreaming) {
      const types = ['FAILED_LOGIN', 'NEW_DEVICE', 'UNUSUAL_LOCATION', 'PRIVILEGE_ESCALATION', 'LARGE_DATA_TRANSFER'];
      timer = setInterval(() => {
        const nextType = types[stepIndex % types.length];
        stepIndex++;
        injectTelemetryEvent(nextType, `Simulated telemetry sensor event: ${nextType} detected.`);
      }, 3500);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [isAutoStreaming]);

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 sm:space-y-8 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-100 uppercase">THREAT DETECTION & TELEMETRY STREAM</h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time event stream evaluation, sequence rule matching, and dynamic risk engine triggers.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={() => setIsAutoStreaming(!isAutoStreaming)}
            className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-bold font-mono transition-all border ${
              isAutoStreaming
                ? 'bg-amber-950 text-amber-400 border-amber-800 animate-pulse'
                : 'bg-slate-900 text-slate-300 border-slate-800 hover:border-slate-700'
            }`}
          >
            {isAutoStreaming ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
            <span>{isAutoStreaming ? 'PAUSE AUTO-STREAM' : 'AUTO-STREAM TELEMETRY'}</span>
          </button>
        </div>
      </div>

      {/* Inject Telemetry Control Card */}
      <div className="glass-panel p-6 rounded-2xl border border-cyan-500/30 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
            <Radio className="w-4 h-4 text-cyan-400" />
            <span>TELEMETRY EVENT INJECTION CONTROLLER</span>
          </h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div>
            <label className="block text-slate-400 font-mono mb-1">Select Event Type</label>
            <select
              value={selectedEventType}
              onChange={(e) => setSelectedEventType(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
            >
              <option value="FAILED_LOGIN">FAILED_LOGIN</option>
              <option value="SUCCESSFUL_LOGIN">SUCCESSFUL_LOGIN</option>
              <option value="NEW_DEVICE">NEW_DEVICE</option>
              <option value="UNUSUAL_LOCATION">UNUSUAL_LOCATION</option>
              <option value="PRIVILEGE_ESCALATION">PRIVILEGE_ESCALATION</option>
              <option value="LARGE_DATA_TRANSFER">LARGE_DATA_TRANSFER</option>
              <option value="SUSPICIOUS_PROCESS">SUSPICIOUS_PROCESS</option>
              <option value="UNUSUAL_ACCESS">UNUSUAL_ACCESS</option>
            </select>
          </div>

          <div className="md:col-span-2">
            <label className="block text-slate-400 font-mono mb-1">Custom Event Details (Optional)</label>
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
              <input
                type="text"
                placeholder="e.g. Out-of-band role escalation requested from unknown IP 198.51.100.42..."
                value={customDetails}
                onChange={(e) => setCustomDetails(e.target.value)}
                className="flex-1 min-w-0 px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
              />
              <button
                onClick={handleInjectTelemetry}
                disabled={isInjecting}
                className="px-5 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 font-bold text-xs flex items-center justify-center space-x-1 shrink-0 glow-cyan justify-center"
              >
                <Plus className={`w-4 h-4 ${isInjecting ? 'animate-spin' : ''}`} />
                <span>Inject Event</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Top Banner: Detection Alert */}
      <div className="glass-panel p-4 sm:p-6 rounded-2xl border border-rose-500/50 bg-gradient-to-r from-rose-950/40 via-slate-900 to-slate-950 space-y-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div className="flex items-start sm:items-center space-x-3">
            <span className="flex h-3 w-3 relative mt-1 sm:mt-0 shrink-0">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-3 w-3 bg-rose-500"></span>
            </span>
            <h3 className="text-sm sm:text-base font-bold text-rose-400 uppercase tracking-wider leading-snug">
              THREAT RULE DETECTED: POSSIBLE ACCOUNT COMPROMISE & DATA EXFILTRATION
            </h3>
          </div>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <span className="px-2.5 py-1 rounded bg-rose-950 text-rose-400 font-mono text-xs font-bold border border-rose-800">
              Confidence: 92%
            </span>
            <span className="px-2.5 py-1 rounded bg-rose-950 text-rose-400 font-mono text-xs font-bold border border-rose-800">
              Severity: CRITICAL
            </span>
          </div>
        </div>

        <p className="text-xs text-slate-300 leading-relaxed">
          <strong>Detection Reason:</strong> Multiple authentication anomalies (15 failed logins + offshore IP) followed by elevated domain admin privileges and 4.8 GB outbound encrypted transfer.
        </p>

        {/* Dynamic Risk Transition Indicator */}
        <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-xs font-mono">
          <span className="text-slate-400">Dynamic Risk Score Engine State:</span>
          <div className="flex flex-wrap items-center gap-2 sm:gap-3">
            <span className="text-amber-400">Previous: 78 / 100</span>
            <ArrowRight className="w-4 h-4 text-cyan-400 shrink-0" />
            <span className="text-rose-400 font-bold">Updated: {riskData?.overallRiskScore ?? 91} / 100 (+13 pts)</span>
          </div>
        </div>
      </div>

      {/* Telemetry Stream Log Table */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
            <Radio className="w-4 h-4 text-cyan-400" />
            <span>REAL-TIME MOCK TELEMETRY STREAM</span>
          </h3>
          <span className="text-xs font-mono text-slate-400">{telemetryStream.length} Events Logged</span>
        </div>

        <div className="space-y-2 max-h-96 overflow-y-auto">
          {telemetryStream.map((event) => (
            <div
              key={event.id}
              className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs"
            >
              <div className="flex items-center space-x-3 shrink-0">
                <span className="font-mono text-slate-500">{event.timestamp}</span>
                <span
                  className={`font-mono px-2 py-0.5 rounded font-bold border ${
                    event.severity === 'CRITICAL'
                      ? 'bg-rose-950 text-rose-400 border-rose-800'
                      : event.severity === 'HIGH'
                      ? 'bg-amber-950 text-amber-400 border-amber-800'
                      : 'bg-blue-950 text-blue-400 border-blue-800'
                  }`}
                >
                  {event.eventType}
                </span>
              </div>

              <div className="flex-1 font-mono text-slate-300 truncate">{event.details}</div>

              <div className="flex items-center space-x-3 text-[11px] font-mono text-slate-400 shrink-0">
                <span>IP: {event.sourceIp}</span>
                <span>User: {event.user}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
