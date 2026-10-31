import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import {
  Laptop,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ArrowLeft,
  RefreshCw,
  Clock,
  User,
  Zap,
  Activity,
  CheckCircle2,
  XCircle,
  ExternalLink,
  Filter,
  Terminal,
  FileText,
  AlertCircle,
  Play,
  Lock,
  Unlock,
  LogOut,
  FolderX,
  KeyRound,
  FileSearch,
  ShieldX,
  X,
  Share2,
  EyeOff
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import { EndpointDevice, EndpointEvent, RemediationCommand, DeviceDetection } from '../types';

export const DeviceDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { token, activeOrg, addNotification } = useApp();

  const [device, setDevice] = useState<EndpointDevice | null>(null);
  const [events, setEvents] = useState<EndpointEvent[]>([]);
  const [commands, setCommands] = useState<RemediationCommand[]>([]);
  const [detection, setDetection] = useState<DeviceDetection | null>(null);
  const [loading, setLoading] = useState(true);
  const [eventFilter, setEventFilter] = useState('ALL');

  // Remediation Action Modal State
  const [selectedAction, setSelectedAction] = useState<string | null>(null);
  const [actionParams, setActionParams] = useState<Record<string, any>>({});
  const [isExecuting, setIsExecuting] = useState(false);
  const [commandFeedback, setCommandFeedback] = useState<{
    status: 'success' | 'error' | 'pending';
    message: string;
    details?: string;
  } | null>(null);

  // Collaborative Sharing State
  const [sharingPattern, setSharingPattern] = useState(false);
  const [shareResult, setShareResult] = useState<any>(null);

  const handleShareSanitizedPattern = async () => {
    if (!device || !token) return;
    setSharingPattern(true);
    try {
      const res = await fetch('/api/privacy/share-endpoint-pattern', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ deviceId: device.id, incidentId: detection?.incidentId })
      });
      const data = await res.json();
      if (res.ok) {
        setShareResult(data);
        addNotification(
          'Pattern Sanitized & Shared',
          `Threat Pattern ${data.pattern?.patternCode} anchored to DLT ledger and shared across collaborative network.`,
          'SUCCESS',
          '/collaborative-network'
        );
      } else {
        alert(data.message || 'Failed to share pattern');
      }
    } catch (err: any) {
      alert(err.message);
    } finally {
      setSharingPattern(false);
    }
  };

  const fetchDeviceData = async () => {
    if (!id || !token) return;
    try {
      const [devRes, detRes] = await Promise.all([
        fetch(`/api/devices/${id}`, {
          headers: { Authorization: `Bearer ${token}` }
        }),
        fetch(`/api/devices/${id}/detection`, {
          headers: { Authorization: `Bearer ${token}` }
        })
      ]);

      if (devRes.ok) {
        const data = await devRes.json();
        setDevice(data.device);
        setEvents(data.recentEvents || []);
        setCommands(data.commands || []);
      } else if (devRes.status === 404) {
        navigate('/endpoints');
        return;
      }

      if (detRes.ok) {
        const detData = await detRes.json();
        setDetection(detData.detection || null);
      }
    } catch (err) {
      console.error('Failed to load device details:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDeviceData();
    const interval = setInterval(fetchDeviceData, 3000);
    return () => clearInterval(interval);
  }, [id, token]);

  const getSeverityBand = (risk: number) => {
    if (risk >= 80) return 'CRITICAL';
    if (risk >= 65) return 'HIGH';
    if (risk >= 45) return 'MEDIUM';
    return 'LOW';
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'Healthy':
        return (
          <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-950/60 text-emerald-400 border border-emerald-500/40">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Healthy</span>
          </span>
        );
      case 'Suspicious':
        return (
          <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-amber-950/60 text-amber-400 border border-amber-500/40">
            <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
            <span>Suspicious</span>
          </span>
        );
      case 'Compromised':
        return (
          <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-rose-950/80 text-rose-300 border border-rose-500/60 shadow-lg shadow-rose-950/50">
            <span className="w-2 h-2 rounded-full bg-rose-400 animate-ping" />
            <span>Compromised</span>
          </span>
        );
      case 'Isolated':
        return (
          <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-purple-950/60 text-purple-300 border border-purple-500/40">
            <span className="w-2 h-2 rounded-full bg-purple-400" />
            <span>Isolated</span>
          </span>
        );
      case 'Remediated':
        return (
          <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-cyan-950/60 text-cyan-300 border border-cyan-500/40">
            <span className="w-2 h-2 rounded-full bg-cyan-400" />
            <span>Remediated</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-slate-900 text-slate-400 border border-slate-700">
            <span className="w-2 h-2 rounded-full bg-slate-500" />
            <span>Offline</span>
          </span>
        );
    }
  };

  const handleOpenRemediationModal = (action: string) => {
    setSelectedAction(action);
    setCommandFeedback(null);
    if (action === 'quarantine_file') {
      setActionParams({ filename: 'suspicious_payload.bin' });
    } else if (action === 'kill_process') {
      setActionParams({ processName: 'demo_suspicious' });
    } else {
      setActionParams({});
    }
  };

  const handleExecuteRemediation = async () => {
    if (!device || !selectedAction || !token) return;

    setIsExecuting(true);
    setCommandFeedback({ status: 'pending', message: 'Signing HMAC-SHA256 command and transmitting to agent...' });

    try {
      const res = await fetch('/api/commands/issue', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({
          deviceId: device.id,
          action: selectedAction,
          params: actionParams
        })
      });

      const data = await res.json();

      if (res.ok) {
        setCommandFeedback({
          status: 'success',
          message: data.message || `Remediation action "${selectedAction}" executed successfully.`,
          details: `Command ID: ${data.command?.id} • Nonce: ${data.command?.nonce}`
        });

        addNotification(
          `Remediation Dispatched: ${selectedAction}`,
          `Command signed and transmitted to ${device.hostname}.`,
          'SUCCESS'
        );

        fetchDeviceData();
      } else {
        setCommandFeedback({
          status: 'error',
          message: data.message || data.error || 'Failed to issue command.',
          details: data.details ? data.details.join(', ') : undefined
        });

        addNotification(
          'Remediation Rejected',
          data.message || 'Command rejected by safety whitelist.',
          'ALERT'
        );
      }
    } catch (err: any) {
      setCommandFeedback({
        status: 'error',
        message: err.message || 'Network communication error.'
      });
    } finally {
      setIsExecuting(false);
    }
  };

  const filteredEvents = events.filter((e) => {
    if (eventFilter === 'ALL') return true;
    if (eventFilter === 'CRITICAL') return e.severity === 'CRITICAL';
    if (eventFilter === 'HIGH') return e.severity === 'HIGH';
    if (eventFilter === 'AUTH') return e.event_type.includes('LOGIN') || e.event_type.includes('AUTH');
    if (eventFilter === 'PROCESS') return e.event_type.includes('PROCESS');
    return true;
  });

  if (loading && !device) {
    return (
      <div className="p-8 max-w-7xl mx-auto flex items-center justify-center min-h-[50vh]">
        <div className="flex items-center space-x-3 text-cyan-400 text-sm font-mono">
          <RefreshCw className="w-5 h-5 animate-spin" />
          <span>Connecting to Endpoint Diagnostics Channel...</span>
        </div>
      </div>
    );
  }

  if (!device) {
    return (
      <div className="p-8 max-w-7xl mx-auto space-y-4">
        <div className="bg-rose-950/40 border border-rose-800 p-6 rounded-2xl text-center space-y-2">
          <AlertCircle className="w-8 h-8 text-rose-400 mx-auto" />
          <h2 className="text-base font-bold text-slate-100">Workstation Not Found</h2>
          <p className="text-xs text-slate-400">Endpoint ID "{id}" was not found or is inaccessible.</p>
          <Link
            to="/endpoints"
            className="inline-flex items-center space-x-1.5 text-xs text-cyan-400 hover:text-cyan-300 font-semibold pt-2"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Return to Fleet Console</span>
          </Link>
        </div>
      </div>
    );
  }

  const sevBand = getSeverityBand(device.risk);

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 max-w-7xl mx-auto">
      {/* Top Breadcrumb & Controls */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center space-x-3">
          <button
            onClick={() => navigate('/endpoints')}
            className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 transition-all"
            title="Back to Endpoints"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-[10px] font-mono uppercase tracking-wider text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800">
                MODULE 8 • ENDPOINT REMEDIATION CONSOLE
              </span>
              <span className="text-xs text-slate-500 font-mono">ID: {device.id}</span>
            </div>
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-100 flex items-center space-x-2 mt-1">
              <span>{device.hostname}</span>
              <span className="text-xs font-mono font-normal text-slate-400">({device.os})</span>
            </h1>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={fetchDeviceData}
            className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 transition-all"
            title="Refresh Diagnostics"
          >
            <RefreshCw className="w-4 h-4" />
          </button>

          <Link
            to="/response-center"
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 text-xs font-semibold rounded-lg shadow-lg shadow-cyan-500/20 transition-all"
          >
            <Zap className="w-3.5 h-3.5" />
            <span>Response Center</span>
          </Link>
        </div>
      </div>

      {/* Device Overview Banner */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Status Card */}
        <div className="bg-[#0F1420] border border-slate-800 rounded-xl p-4 space-y-2">
          <span className="text-[10px] font-mono uppercase text-slate-400 tracking-wider">LIFECYCLE STATUS</span>
          <div>{getStatusBadge(device.status)}</div>
          <p className="text-[11px] text-slate-500 font-mono">
            Enrolled: {new Date(device.enrolled_at).toLocaleDateString()}
          </p>
        </div>

        {/* Risk Score Card */}
        <div className="bg-[#0F1420] border border-slate-800 rounded-xl p-4 space-y-2">
          <span className="text-[10px] font-mono uppercase text-slate-400 tracking-wider">ENDPOINT RISK SCORE</span>
          <div className="flex items-baseline space-x-2">
            <span
              className={`text-2xl font-black font-mono ${
                sevBand === 'CRITICAL'
                  ? 'text-rose-400'
                  : sevBand === 'HIGH'
                  ? 'text-orange-400'
                  : sevBand === 'MEDIUM'
                  ? 'text-amber-400'
                  : 'text-emerald-400'
              }`}
            >
              {device.risk}
            </span>
            <span className="text-xs text-slate-500 font-mono">/ 100</span>
            <span
              className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                sevBand === 'CRITICAL'
                  ? 'bg-rose-950 text-rose-300 border border-rose-800'
                  : sevBand === 'HIGH'
                  ? 'bg-orange-950 text-orange-300 border border-orange-800'
                  : sevBand === 'MEDIUM'
                  ? 'bg-amber-950 text-amber-300 border border-amber-800'
                  : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
              }`}
            >
              {sevBand}
            </span>
          </div>
          <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
            <div
              className={`h-full transition-all ${
                sevBand === 'CRITICAL'
                  ? 'bg-rose-500'
                  : sevBand === 'HIGH'
                  ? 'bg-orange-500'
                  : sevBand === 'MEDIUM'
                  ? 'bg-amber-500'
                  : 'bg-emerald-500'
              }`}
              style={{ width: `${Math.min(device.risk, 100)}%` }}
            />
          </div>
        </div>

        {/* Assigned Owner */}
        <div className="bg-[#0F1420] border border-slate-800 rounded-xl p-4 space-y-1">
          <span className="text-[10px] font-mono uppercase text-slate-400 tracking-wider">ASSIGNED EMPLOYEE</span>
          <div className="flex items-center space-x-2 pt-1">
            <User className="w-4 h-4 text-cyan-400" />
            <span className="text-xs font-semibold text-slate-200">{device.user_name || device.user_id}</span>
          </div>
          <p className="text-[11px] text-slate-400 font-mono truncate">{device.user_email || 'No email registered'}</p>
        </div>

        {/* Telemetry Heartbeat */}
        <div className="bg-[#0F1420] border border-slate-800 rounded-xl p-4 space-y-1">
          <span className="text-[10px] font-mono uppercase text-slate-400 tracking-wider">AGENT TELEMETRY BEAT</span>
          <div className="flex items-center space-x-2 pt-1 font-mono text-xs text-slate-200">
            <Clock className="w-4 h-4 text-emerald-400" />
            <span>{new Date(device.last_seen).toLocaleTimeString()}</span>
          </div>
          <p className="text-[11px] text-slate-500 font-mono">
            {events.length} Telemetry Events in sliding buffer
          </p>
        </div>
      </div>

      {/* Detection Banner & Explainability Waterfall */}
      {detection && (
        <div
          className={`border rounded-2xl p-6 space-y-6 ${
            detection.detected
              ? 'bg-rose-950/20 border-rose-500/50 shadow-xl shadow-rose-950/30'
              : 'bg-[#0F1420] border-slate-800'
          }`}
        >
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
            <div className="flex items-start space-x-3">
              <div
                className={`p-2 rounded-xl mt-0.5 ${
                  detection.detected ? 'bg-rose-950 border border-rose-700 text-rose-400' : 'bg-slate-900 text-cyan-400'
                }`}
              >
                {detection.detected ? <ShieldAlert className="w-6 h-6 animate-pulse" /> : <ShieldCheck className="w-6 h-6" />}
              </div>
              <div>
                <div className="flex items-center space-x-2">
                  <span
                    className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                      detection.detected
                        ? 'bg-rose-950 text-rose-300 border border-rose-700'
                        : 'bg-emerald-950 text-emerald-300 border border-emerald-700'
                    }`}
                  >
                    {detection.detected ? 'THREAT DETECTED' : 'NORMAL TELEMETRY BASELINE'}
                  </span>
                  <span className="text-xs font-mono text-slate-400">
                    Confidence: <strong className="text-cyan-400">{detection.confidence}%</strong>
                  </span>
                </div>
                <h2 className="text-base font-bold text-slate-100 mt-1">{detection.title}</h2>
                <p className="text-xs text-slate-400">{detection.summary}</p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2 shrink-0 self-start sm:self-auto">
              <button
                type="button"
                onClick={handleShareSanitizedPattern}
                disabled={sharingPattern}
                className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-purple-700 to-indigo-700 hover:from-purple-600 hover:to-indigo-600 text-slate-100 text-xs font-semibold shadow-md shadow-purple-950/50 transition-all"
              >
                <Share2 className="w-3.5 h-3.5 text-purple-200" />
                <span>{sharingPattern ? 'Sanitizing...' : 'Share Sanitized Pattern'}</span>
              </button>

              {detection.incidentId && (
                <Link
                  to="/incidents"
                  className="inline-flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-rose-950 hover:bg-rose-900 border border-rose-700 text-rose-200 text-xs font-semibold transition-all"
                >
                  <span>Investigate Incident</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </Link>
              )}
            </div>
          </div>

          {/* Matched Rules Table */}
          {detection.matchedRules && detection.matchedRules.length > 0 && (
            <div className="space-y-3">
              <h3 className="text-xs font-mono uppercase text-slate-400 tracking-wider">
                MATCHED HEURISTIC RULES IN SLIDING WINDOW
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {detection.matchedRules.map((rule) => (
                  <div
                    key={rule.ruleId}
                    className="bg-[#0B0F17] p-3.5 rounded-xl border border-rose-900/40 space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-rose-400">{rule.ruleId}</span>
                      <span className="text-[10px] font-mono bg-rose-950 text-rose-300 px-2 py-0.5 rounded border border-rose-800">
                        +{rule.points} Risk Pts
                      </span>
                    </div>
                    <h4 className="text-xs font-bold text-slate-200">{rule.name}</h4>
                    <p className="text-[11px] text-slate-400">{rule.description}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Explainability Waterfall */}
          {detection.factorContributions && detection.factorContributions.length > 0 && (
            <div className="space-y-3">
              <h3 className="text-xs font-mono uppercase text-slate-400 tracking-wider">
                EXPLAINABILITY RISK WATERFALL (CONTRIBUTION FACTORS)
              </h3>
              <div className="space-y-2">
                {detection.factorContributions.map((fc) => (
                  <div
                    key={fc.id}
                    className="bg-[#0B0F17] p-3 rounded-xl border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                  >
                    <div className="space-y-1 flex-1">
                      <div className="flex items-center space-x-2">
                        <span className="text-[10px] font-mono font-bold text-cyan-400 uppercase">
                          {fc.category}
                        </span>
                        <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
                          {fc.severity}
                        </span>
                      </div>
                      <p className="text-xs text-slate-300">{fc.explanation}</p>
                    </div>

                    <div className="flex items-center space-x-3 shrink-0">
                      <div className="w-24 bg-slate-800 h-2 rounded-full overflow-hidden">
                        <div
                          className="bg-cyan-500 h-full"
                          style={{ width: `${Math.min(fc.points * 2.5, 100)}%` }}
                        />
                      </div>
                      <span className="font-mono text-xs font-bold text-cyan-400 w-12 text-right">
                        +{fc.points} pts
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Split Grid: Live Event Feed & Remote Remediation Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Live Event Feed */}
        <div className="lg:col-span-6 bg-[#0F1420] border border-slate-800 rounded-2xl p-6 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
            <div className="flex items-center space-x-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">
                LIVE AGENT TELEMETRY FEED
              </h3>
            </div>

            {/* Filter Tabs */}
            <div className="flex items-center space-x-1.5 text-[10px] font-mono">
              {['ALL', 'CRITICAL', 'HIGH', 'AUTH', 'PROCESS'].map((f) => (
                <button
                  key={f}
                  onClick={() => setEventFilter(f)}
                  className={`px-2 py-1 rounded transition-all ${
                    eventFilter === f
                      ? 'bg-cyan-950 text-cyan-400 border border-cyan-800 font-bold'
                      : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                  }`}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
            {filteredEvents.length === 0 ? (
              <div className="p-8 text-center text-slate-500 text-xs font-mono">
                No events match filter criteria.
              </div>
            ) : (
              filteredEvents.map((e) => (
                <div
                  key={e.id}
                  className="bg-[#0B0F17] p-3 rounded-xl border border-slate-800/80 hover:border-slate-700 transition-all space-y-1"
                >
                  <div className="flex items-center justify-between text-[11px] font-mono">
                    <div className="flex items-center space-x-2">
                      <span
                        className={`px-1.5 py-0.5 rounded font-bold text-[9px] ${
                          e.severity === 'CRITICAL'
                            ? 'bg-rose-950 text-rose-300 border border-rose-800'
                            : e.severity === 'HIGH'
                            ? 'bg-orange-950 text-orange-300 border border-orange-800'
                            : e.severity === 'MEDIUM'
                            ? 'bg-amber-950 text-amber-300 border border-amber-800'
                            : 'bg-slate-800 text-slate-300'
                        }`}
                      >
                        {e.severity}
                      </span>
                      <span className="font-semibold text-slate-300">{e.event_type}</span>
                    </div>
                    <span className="text-slate-500">{new Date(e.timestamp).toLocaleTimeString()}</span>
                  </div>
                  <p className="text-xs text-slate-400 font-mono pl-1">{e.details}</p>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right: Remote Remediation Control Panel & History */}
        <div className="lg:col-span-6 space-y-6">
          {/* Action Center: Whitelisted Commands */}
          <div className="bg-[#0F1420] border border-cyan-500/40 rounded-2xl p-6 shadow-xl shadow-cyan-950/20 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Zap className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">
                  REMOTE REMEDIATION ACTIONS
                </h3>
              </div>
              <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/80 px-2 py-0.5 rounded border border-emerald-800">
                HMAC-AUTHENTICATED
              </span>
            </div>

            <p className="text-xs text-slate-400">
              Dispatches cryptographically signed commands directly to the endpoint agent over the real-time WebSocket channel.
            </p>

            {/* Whitelisted Command Action Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {/* 1. Kill Process */}
              <button
                type="button"
                onClick={() => handleOpenRemediationModal('kill_process')}
                className="p-3 rounded-xl bg-slate-900 hover:bg-rose-950/60 border border-slate-800 hover:border-rose-500/60 text-left transition-all space-y-1 group"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-rose-300 group-hover:text-rose-200 flex items-center space-x-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                    <span>Kill Suspicious Process</span>
                  </span>
                  <span className="text-[9px] font-mono px-1 rounded bg-rose-950 text-rose-400 border border-rose-800">
                    STOP
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 leading-tight">
                  Terminates harmless tracked process <code>demo_suspicious</code>.
                </p>
              </button>

              {/* 2. Isolate Device */}
              <button
                type="button"
                onClick={() => handleOpenRemediationModal('isolate_device')}
                className="p-3 rounded-xl bg-slate-900 hover:bg-purple-950/60 border border-slate-800 hover:border-purple-500/60 text-left transition-all space-y-1 group"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-purple-300 group-hover:text-purple-200 flex items-center space-x-1.5">
                    <Lock className="w-3.5 h-3.5 text-purple-400" />
                    <span>Isolate Workstation</span>
                  </span>
                  <span className="text-[9px] font-mono px-1 rounded bg-purple-950 text-purple-400 border border-purple-800">
                    MESH
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 leading-tight">
                  Simulates full network isolation; telemetry stream remains live.
                </p>
              </button>

              {/* 3. Release Isolation */}
              <button
                type="button"
                onClick={() => handleOpenRemediationModal('release_isolation')}
                className="p-3 rounded-xl bg-slate-900 hover:bg-blue-950/60 border border-slate-800 hover:border-blue-500/60 text-left transition-all space-y-1 group"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-blue-300 group-hover:text-blue-200 flex items-center space-x-1.5">
                    <Unlock className="w-3.5 h-3.5 text-blue-400" />
                    <span>Release Isolation</span>
                  </span>
                  <span className="text-[9px] font-mono px-1 rounded bg-blue-950 text-blue-400 border border-blue-800">
                    UNBLOCK
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 leading-tight">
                  Restores normal network egress and communication.
                </p>
              </button>

              {/* 4. Force Logout */}
              <button
                type="button"
                onClick={() => handleOpenRemediationModal('force_logout')}
                className="p-3 rounded-xl bg-slate-900 hover:bg-amber-950/60 border border-slate-800 hover:border-amber-500/60 text-left transition-all space-y-1 group"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-amber-300 group-hover:text-amber-200 flex items-center space-x-1.5">
                    <LogOut className="w-3.5 h-3.5 text-amber-400" />
                    <span>Force Session Logout</span>
                  </span>
                  <span className="text-[9px] font-mono px-1 rounded bg-amber-950 text-amber-400 border border-amber-800">
                    AUTH
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 leading-tight">
                  Invalidates user sessions and clears workstation tokens.
                </p>
              </button>

              {/* 5. Quarantine File */}
              <button
                type="button"
                onClick={() => handleOpenRemediationModal('quarantine_file')}
                className="p-3 rounded-xl bg-slate-900 hover:bg-cyan-950/60 border border-slate-800 hover:border-cyan-500/60 text-left transition-all space-y-1 group"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-cyan-300 group-hover:text-cyan-200 flex items-center space-x-1.5">
                    <FolderX className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Quarantine File</span>
                  </span>
                  <span className="text-[9px] font-mono px-1 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
                    SANDBOX
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 leading-tight">
                  Moves payload inside agent/sandbox/ to quarantine/.
                </p>
              </button>

              {/* 6. Reset Credentials */}
              <button
                type="button"
                onClick={() => handleOpenRemediationModal('reset_credentials')}
                className="p-3 rounded-xl bg-slate-900 hover:bg-emerald-950/60 border border-slate-800 hover:border-emerald-500/60 text-left transition-all space-y-1 group"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-emerald-300 group-hover:text-emerald-200 flex items-center space-x-1.5">
                    <KeyRound className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Reset Credentials</span>
                  </span>
                  <span className="text-[9px] font-mono px-1 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                    EXPIRE
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 leading-tight">
                  Forces user to set a new password on next login.
                </p>
              </button>
            </div>

            {/* 7. Collect Diagnostics */}
            <button
              type="button"
              onClick={() => handleOpenRemediationModal('collect_diagnostics')}
              className="w-full py-2.5 px-3 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 flex items-center justify-center space-x-2 transition-all font-semibold"
            >
              <FileSearch className="w-4 h-4 text-cyan-400" />
              <span>Collect Recent Agent Diagnostics Buffer</span>
            </button>
          </div>

          {/* Remediation History Panel */}
          <div className="bg-[#0F1420] border border-slate-800 rounded-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">
                  DISPATCHED COMMAND AUDIT
                </h3>
              </div>
              <span className="text-xs font-mono text-cyan-400">{commands.length} Commands</span>
            </div>

            <div className="space-y-3 max-h-[300px] overflow-y-auto pr-1">
              {commands.length === 0 ? (
                <div className="p-8 text-center text-slate-500 text-xs font-mono">
                  No remediation commands dispatched to this endpoint yet.
                </div>
              ) : (
                commands.map((cmd) => (
                  <div
                    key={cmd.id}
                    className="bg-[#0B0F17] p-3.5 rounded-xl border border-slate-800 space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-cyan-400">{cmd.action}</span>
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                          cmd.status === 'Executed'
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                            : cmd.status === 'Sent' || cmd.status === 'Pending'
                            ? 'bg-blue-950 text-blue-300 border border-blue-800'
                            : 'bg-rose-950 text-rose-300 border border-rose-800'
                        }`}
                      >
                        {cmd.status}
                      </span>
                    </div>

                    <div className="text-[11px] font-mono text-slate-400 space-y-0.5">
                      <div>Issued By: <span className="text-slate-200">{cmd.issued_by}</span></div>
                      <div>Time: <span className="text-slate-300">{new Date(cmd.issued_at).toLocaleTimeString()}</span></div>
                      <div className="text-[10px] text-slate-500 truncate">Nonce: {cmd.nonce}</div>
                    </div>

                    {cmd.result && (
                      <div className="bg-slate-900/80 p-2 rounded border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto">
                        <strong>Agent Result:</strong> {cmd.result}
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Confirmation Modal */}
      {selectedAction && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0F1420] border border-cyan-500/40 rounded-2xl p-6 max-w-lg w-full shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
                <Zap className="w-4 h-4 text-cyan-400" />
                <span>CONFIRM REMOTE REMEDIATION COMMAND</span>
              </h3>
              <button
                type="button"
                onClick={() => {
                  setSelectedAction(null);
                  setCommandFeedback(null);
                }}
                className="text-slate-500 hover:text-slate-300 text-sm"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="bg-[#0B0F17] p-3 rounded-xl border border-slate-800 space-y-1 font-mono">
                <div>Target Device: <strong className="text-slate-200">{device.hostname} ({device.id})</strong></div>
                <div>Action: <strong className="text-cyan-400">{selectedAction}</strong></div>
                <div>Authorization: <span className="text-emerald-400">Admin HMAC-SHA256 Signed</span></div>
                <div>TTL: <span className="text-slate-400">60 seconds with anti-replay nonce</span></div>
              </div>

              {selectedAction === 'quarantine_file' && (
                <div>
                  <label className="block text-slate-400 mb-1 font-mono">Quarantine Target Filename (inside agent/sandbox/):</label>
                  <input
                    type="text"
                    value={actionParams.filename || ''}
                    onChange={(e) => setActionParams({ ...actionParams, filename: e.target.value })}
                    className="w-full bg-[#0B0F17] border border-slate-700 rounded-lg px-3 py-2 text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
                    placeholder="suspicious_payload.bin"
                  />
                  <span className="text-[10px] text-slate-500 mt-1 block">
                    Path traversal sequences ('..', absolute paths) will be rejected by sandbox security.
                  </span>
                </div>
              )}

              {selectedAction === 'kill_process' && (
                <div>
                  <label className="block text-slate-400 mb-1 font-mono">Process Name Target:</label>
                  <input
                    type="text"
                    value={actionParams.processName || 'demo_suspicious'}
                    disabled
                    className="w-full bg-[#0B0F17] border border-slate-800 rounded-lg px-3 py-2 text-slate-400 font-mono text-xs cursor-not-allowed"
                  />
                  <span className="text-[10px] text-amber-400/80 mt-1 block">
                    Security Whitelist: Restricted strictly to harmless tracked "demo_suspicious" process.
                  </span>
                </div>
              )}

              <p className="text-slate-400 text-xs">
                {selectedAction === 'kill_process' && 'Terminates the active demonstration process on the remote workstation.'}
                {selectedAction === 'isolate_device' && 'Sets the simulated network isolation flag on the workstation.'}
                {selectedAction === 'release_isolation' && 'Lifts the simulated isolation flag and restores communication.'}
                {selectedAction === 'force_logout' && 'Revokes employee tokens and terminates active session.'}
                {selectedAction === 'quarantine_file' && 'Moves file into the isolated quarantine subfolder.'}
                {selectedAction === 'reset_credentials' && 'Forces user to set a new password upon subsequent login.'}
                {selectedAction === 'collect_diagnostics' && 'Fetches recent agent buffer telemetry.'}
              </p>

              {commandFeedback && (
                <div
                  className={`p-3 rounded-xl border text-xs font-mono space-y-1 ${
                    commandFeedback.status === 'success'
                      ? 'bg-emerald-950/60 border-emerald-500/60 text-emerald-300'
                      : commandFeedback.status === 'pending'
                      ? 'bg-cyan-950/60 border-cyan-500/60 text-cyan-300'
                      : 'bg-rose-950/60 border-rose-500/60 text-rose-300'
                  }`}
                >
                  <div className="font-bold">{commandFeedback.message}</div>
                  {commandFeedback.details && (
                    <div className="text-[11px] text-slate-400">{commandFeedback.details}</div>
                  )}
                </div>
              )}
            </div>

            <div className="flex items-center justify-end space-x-2 pt-2 border-t border-slate-800">
              <button
                type="button"
                onClick={() => {
                  setSelectedAction(null);
                  setCommandFeedback(null);
                }}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium"
              >
                Close
              </button>
              <button
                type="button"
                onClick={handleExecuteRemediation}
                disabled={isExecuting}
                className="px-4 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold transition-all disabled:opacity-50 flex items-center space-x-1.5"
              >
                {isExecuting ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Transmitting...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5 fill-slate-950" />
                    <span>Confirm & Execute Command</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Collaborative Share Result Modal */}
      {shareResult && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0F1420] border border-purple-500/50 rounded-2xl p-6 max-w-lg w-full shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
                <Share2 className="w-4 h-4 text-purple-400" />
                <span>SANITIZED THREAT PATTERN BROADCAST</span>
              </h3>
              <button
                type="button"
                onClick={() => setShareResult(null)}
                className="text-slate-500 hover:text-slate-300 text-sm"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="bg-[#0B0F17] p-3 rounded-xl border border-slate-800 space-y-1 font-mono">
                <div>Pattern Code: <strong className="text-purple-400">{shareResult.pattern?.patternCode}</strong></div>
                <div>Hash: <span className="text-slate-400 text-[10px] break-all">{shareResult.pattern?.hash}</span></div>
                <div>Behavior Sequence: <span className="text-emerald-400">{shareResult.pattern?.patternSequence?.join(' ➔ ')}</span></div>
              </div>

              <div className="p-3 bg-purple-950/20 border border-purple-800/60 rounded-xl space-y-1.5">
                <div className="font-semibold text-purple-300 flex items-center space-x-1.5">
                  <EyeOff className="w-3.5 h-3.5 text-purple-400" />
                  <span>Privacy Engine Masked Fields (Zero PII Exposed):</span>
                </div>
                <ul className="list-disc list-inside text-[11px] text-slate-400 space-y-0.5">
                  {shareResult.sanitizationResult?.maskedFields?.map((f: string, i: number) => (
                    <li key={i}>{f}</li>
                  ))}
                </ul>
              </div>

              {shareResult.peerCorrelations && shareResult.peerCorrelations.length > 0 && (
                <div className="space-y-1.5">
                  <div className="font-mono text-[10px] text-slate-400 uppercase tracking-wider">
                    Cross-Institutional Peer Correlation:
                  </div>
                  <div className="space-y-1 max-h-36 overflow-y-auto">
                    {shareResult.peerCorrelations.map((c: any, idx: number) => (
                      <div
                        key={idx}
                        className="bg-[#0B0F17] p-2 rounded-lg border border-slate-800 flex items-center justify-between text-[11px] font-mono"
                      >
                        <span className="text-slate-300">{c.targetOrgName}</span>
                        <div className="flex items-center space-x-2">
                          <span
                            className={`px-1.5 py-0.5 rounded font-bold ${
                              c.earlyWarningTriggered
                                ? 'bg-rose-950 text-rose-300 border border-rose-800 animate-pulse'
                                : 'bg-slate-800 text-slate-400'
                            }`}
                          >
                            {c.similarityPercentage}% Match
                          </span>
                          {c.earlyWarningTriggered && (
                            <span className="text-[9px] text-rose-400 font-bold">EARLY WARNING 🔔</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-slate-800">
              <Link
                to="/collaborative-network"
                className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold inline-flex items-center space-x-1"
              >
                <span>Open Collaborative Network</span>
                <ExternalLink className="w-3 h-3" />
              </Link>

              <button
                type="button"
                onClick={() => setShareResult(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
