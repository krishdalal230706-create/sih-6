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
  Pause,
  Landmark,
  ShieldCheck,
  Filter,
  Check,
  RefreshCw
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import { BankSecurityEvent } from '../types';

export const ThreatDetection: React.FC = () => {
  const { telemetryStream, injectTelemetryEvent, riskData, token, addNotification } = useApp();
  const [selectedEventType, setSelectedEventType] = useState<string>('PRIVILEGE_ESCALATION');
  const [customDetails, setCustomDetails] = useState<string>('');
  const [isInjecting, setIsInjecting] = useState(false);
  const [isAutoStreaming, setIsAutoStreaming] = useState(false);

  // Bank Security Events State
  const [bankEvents, setBankEvents] = useState<BankSecurityEvent[]>([]);
  const [loadingBankEvents, setLoadingBankEvents] = useState(false);
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [updatingEventId, setUpdatingEventId] = useState<string | null>(null);

  const fetchBankEvents = async () => {
    if (!token) return;
    try {
      setLoadingBankEvents(true);
      const queryParams = new URLSearchParams();
      if (statusFilter !== 'ALL') queryParams.append('status', statusFilter);
      if (severityFilter !== 'ALL') queryParams.append('severity', severityFilter);

      const res = await fetch(`/api/bank-assets/events?${queryParams.toString()}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setBankEvents(data.events || []);
      }
    } catch (err) {
      console.error('Failed to fetch bank security events:', err);
    } finally {
      setLoadingBankEvents(false);
    }
  };

  useEffect(() => {
    fetchBankEvents();
  }, [token, statusFilter, severityFilter]);

  const handleUpdateStatus = async (
    eventId: string,
    newStatus: 'NEW' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED'
  ) => {
    if (!token) return;
    setUpdatingEventId(eventId);
    try {
      const res = await fetch(`/api/bank-assets/events/${eventId}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ status: newStatus })
      });
      if (res.ok) {
        addNotification('Event Status Updated', `Event ${eventId} transitioned to ${newStatus}`, 'SUCCESS');
        fetchBankEvents();
      }
    } catch (err) {
      console.error('Failed to update event status:', err);
    } finally {
      setUpdatingEventId(null);
    }
  };

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
          <div className="flex items-center gap-2 mb-1">
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-100 uppercase">
              BANK THREAT DETECTION & TELEMETRY STREAM
            </h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-mono bg-cyan-950 text-cyan-400 border border-cyan-800">
              Demo Bank SOC
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Real-time synthetic security event evaluation, payment gateway anomaly correlation, and incident triage.
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

      {/* Top Banner: Detection Alert */}
      <div className="glass-panel p-4 sm:p-6 rounded-2xl border border-rose-500/50 bg-gradient-to-r from-rose-950/40 via-slate-900 to-slate-950 space-y-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div className="flex items-start sm:items-center space-x-3">
            <span className="flex h-3 w-3 relative mt-1 sm:mt-0 shrink-0">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-3 w-3 bg-rose-500"></span>
            </span>
            <h3 className="text-sm sm:text-base font-bold text-rose-400 uppercase tracking-wider leading-snug">
              BANKING THREAT DETECTED: PAYMENT GATEWAY VELOCITY BURST & CREDENTIAL STUFFING
            </h3>
          </div>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <span className="px-2.5 py-1 rounded bg-rose-950 text-rose-400 font-mono text-xs font-bold border border-rose-800">
              Confidence: 94%
            </span>
            <span className="px-2.5 py-1 rounded bg-rose-950 text-rose-400 font-mono text-xs font-bold border border-rose-800">
              Severity: CRITICAL
            </span>
          </div>
        </div>

        <p className="text-xs text-slate-300 leading-relaxed">
          <strong>Detection Reason:</strong> UPI Gateway anomaly (420 micro-debits/min from proxy clusters) correlated with distributed login attempts against NetBanking reverse proxy.
        </p>

        {/* Dynamic Risk Transition Indicator */}
        <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-xs font-mono">
          <span className="text-slate-400">Dynamic Bank Risk Engine State:</span>
          <div className="flex flex-wrap items-center gap-2 sm:gap-3">
            <span className="text-amber-400">Baseline: 62 / 100</span>
            <ArrowRight className="w-4 h-4 text-cyan-400 shrink-0" />
            <span className="text-rose-400 font-bold">Current: {riskData?.overallRiskScore ?? 84} / 100 (HIGH RISK)</span>
          </div>
        </div>
      </div>

      {/* Banking Security Events Stream Table */}
      <div className="glass-panel p-6 rounded-2xl border border-cyan-500/30 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-3">
          <div className="flex items-center space-x-2">
            <Landmark className="w-5 h-5 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
              DEMO BANK SECURITY EVENTS STREAM
            </h3>
            <span className="text-xs font-mono text-slate-400">({bankEvents.length} Active Events)</span>
          </div>

          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400 font-mono">Severity:</span>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-slate-900 border border-slate-700 text-xs text-slate-200 rounded px-2.5 py-1 font-mono focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400 font-mono">Status:</span>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="bg-slate-900 border border-slate-700 text-xs text-slate-200 rounded px-2.5 py-1 font-mono focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Statuses</option>
                <option value="NEW">New</option>
                <option value="INVESTIGATING">Investigating</option>
                <option value="CONTAINED">Contained</option>
                <option value="RESOLVED">Resolved</option>
              </select>
            </div>

            <button
              onClick={fetchBankEvents}
              className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
              title="Refresh Events"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingBankEvents ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/60 text-slate-400 uppercase font-mono">
                <th className="py-2.5 px-3">Event ID</th>
                <th className="py-2.5 px-3">Category</th>
                <th className="py-2.5 px-3">Affected Asset</th>
                <th className="py-2.5 px-3">Detection Source</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Recommended Response</th>
                <th className="py-2.5 px-3 text-right">Triage Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {bankEvents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 font-mono">
                    No banking security events match the current filter.
                  </td>
                </tr>
              ) : (
                bankEvents.map((evt) => (
                  <tr key={evt.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-3 font-mono font-bold text-cyan-400">{evt.id}</td>
                    <td className="py-3 px-3 font-semibold text-slate-200">{evt.eventCategory}</td>
                    <td className="py-3 px-3 text-slate-300">{evt.affectedAssetName || evt.affectedAssetId}</td>
                    <td className="py-3 px-3 font-mono text-slate-400">{evt.detectionSource}</td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        evt.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                        evt.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                        evt.severity === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' :
                        'bg-slate-500/20 text-slate-400 border border-slate-500/30'
                      }`}>
                        {evt.severity}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                        evt.investigationStatus === 'NEW' ? 'bg-rose-500/10 text-rose-400' :
                        evt.investigationStatus === 'INVESTIGATING' ? 'bg-amber-500/10 text-amber-400' :
                        evt.investigationStatus === 'CONTAINED' ? 'bg-blue-500/10 text-blue-400' :
                        'bg-emerald-500/10 text-emerald-400'
                      }`}>
                        {evt.investigationStatus}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-slate-300 max-w-xs truncate" title={evt.recommendedAction}>
                      {evt.recommendedAction}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <div className="flex items-center justify-end gap-1">
                        {evt.investigationStatus === 'NEW' && (
                          <button
                            onClick={() => handleUpdateStatus(evt.id, 'INVESTIGATING')}
                            disabled={updatingEventId === evt.id}
                            className="px-2 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 font-mono text-[10px] border border-amber-500/40"
                          >
                            Investigate
                          </button>
                        )}
                        {evt.investigationStatus === 'INVESTIGATING' && (
                          <button
                            onClick={() => handleUpdateStatus(evt.id, 'CONTAINED')}
                            disabled={updatingEventId === evt.id}
                            className="px-2 py-1 rounded bg-blue-500/20 hover:bg-blue-500/30 text-blue-300 font-mono text-[10px] border border-blue-500/40"
                          >
                            Contain
                          </button>
                        )}
                        {evt.investigationStatus !== 'RESOLVED' && (
                          <button
                            onClick={() => handleUpdateStatus(evt.id, 'RESOLVED')}
                            disabled={updatingEventId === evt.id}
                            className="px-2 py-1 rounded bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 font-mono text-[10px] border border-emerald-500/40"
                          >
                            Resolve
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Inject Telemetry Control Card */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
            <Radio className="w-4 h-4 text-cyan-400" />
            <span>BANK TELEMETRY EVENT INJECTION CONTROLLER</span>
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
              <option value="FAILED_LOGIN">FAILED_LOGIN (NetBanking)</option>
              <option value="SUCCESSFUL_LOGIN">SUCCESSFUL_LOGIN</option>
              <option value="NEW_DEVICE">NEW_DEVICE (Teller Workstation)</option>
              <option value="UNUSUAL_LOCATION">UNUSUAL_LOCATION (Offshore IP)</option>
              <option value="PRIVILEGE_ESCALATION">PRIVILEGE_ESCALATION (Domain Admin)</option>
              <option value="LARGE_DATA_TRANSFER">LARGE_DATA_TRANSFER (CIF Bulk Export)</option>
              <option value="SUSPICIOUS_PROCESS">SUSPICIOUS_PROCESS (EDR Alert)</option>
              <option value="UNUSUAL_ACCESS">UNUSUAL_ACCESS (Core Banking Query)</option>
            </select>
          </div>

          <div className="md:col-span-2">
            <label className="block text-slate-400 font-mono mb-1">Custom Event Details (Optional)</label>
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
              <input
                type="text"
                placeholder="e.g. 15 failed logins followed by privilege escalation on Connaught Place branch..."
                value={customDetails}
                onChange={(e) => setCustomDetails(e.target.value)}
                className="flex-1 min-w-0 px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
              />
              <button
                onClick={handleInjectTelemetry}
                disabled={isInjecting}
                className="px-5 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 font-bold text-xs flex items-center justify-center space-x-1 shrink-0 glow-cyan"
              >
                <Plus className={`w-4 h-4 ${isInjecting ? 'animate-spin' : ''}`} />
                <span>Inject Event</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Telemetry Stream Log Table */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
            <Radio className="w-4 h-4 text-cyan-400" />
            <span>REAL-TIME BANK TELEMETRY SENSOR LOG</span>
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
