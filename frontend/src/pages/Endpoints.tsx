import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Laptop,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Plus,
  Search,
  Filter,
  CheckCircle2,
  ExternalLink,
  Clock,
  User,
  Copy,
  Check,
  Sparkles,
  RotateCcw,
  Flame
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import { EndpointDevice } from '../types';

export const Endpoints: React.FC = () => {
  const { activeOrg, token, devices, fetchDevices, addNotification } = useApp();
  const navigate = useNavigate();

  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [isEnrollModalOpen, setIsEnrollModalOpen] = useState(false);
  const [enrollTargetUser, setEnrollTargetUser] = useState('');
  const [enrollmentCode, setEnrollmentCode] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [generatingCode, setGeneratingCode] = useState(false);
  const [runningDemo, setRunningDemo] = useState(false);
  const [resettingDemo, setResettingDemo] = useState(false);

  const handleRunEndpointDemo = async () => {
    setRunningDemo(true);
    try {
      // Step 1: Trigger Attack Simulation
      const res = await fetch('/api/demo/endpoint-run', { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        addNotification(
          '🚨 Endpoint Attack Injected (Demo)',
          'Simulated multi-stage attack on Alice\'s Laptop (DEV-BANK-01). Alert emitted to SOC.',
          'ALERT',
          '/endpoints/DEV-BANK-01'
        );
        fetchDevices();
        navigate('/endpoints/DEV-BANK-01');

        // Step 2: Auto-trigger remediation after 4 seconds
        setTimeout(async () => {
          try {
            const remRes = await fetch('/api/demo/endpoint-remediate', { method: 'POST' });
            const remData = await remRes.json();
            if (remRes.ok) {
              addNotification(
                '✅ Remote Remediation Executed',
                'Admin killed demo_suspicious & revoked session. Device Remediated. Early warning broadcast to Hospital B.',
                'SUCCESS',
                '/collaborative-network'
              );
              fetchDevices();
            }
          } catch (e) {
            console.error(e);
          } finally {
            setRunningDemo(false);
          }
        }, 4000);
      }
    } catch (err: any) {
      alert(err.message);
      setRunningDemo(false);
    }
  };

  const handleResetEndpointDemo = async () => {
    setResettingDemo(true);
    try {
      const res = await fetch('/api/demo/endpoint-reset', { method: 'POST' });
      if (res.ok) {
        addNotification(
          'Baseline Restored',
          'DEV-BANK-01 restored to Healthy baseline posture (Risk 18). Clean state active.',
          'SUCCESS'
        );
        fetchDevices();
      }
    } catch (err: any) {
      alert(err.message);
    } finally {
      setResettingDemo(false);
    }
  };

  useEffect(() => {
    fetchDevices();
    const interval = setInterval(fetchDevices, 4000);
    return () => clearInterval(interval);
  }, [token, activeOrg]);

  const handleGenerateCode = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;
    setGeneratingCode(true);
    try {
      const res = await fetch('/api/devices/enrollment-code', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ userId: enrollTargetUser })
      });
      const data = await res.json();
      if (res.ok) {
        setEnrollmentCode(data.enrollmentCode);
        addNotification(
          'Enrollment Code Created',
          `Code ${data.enrollmentCode} generated for new endpoint onboarding.`,
          'SUCCESS'
        );
      } else {
        alert(data.message || 'Failed to generate enrollment code');
      }
    } catch (err: any) {
      alert(err.message || 'Network error');
    } finally {
      setGeneratingCode(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Severity Band Helper: >=80 Critical, >=65 High, >=45 Medium, else Low
  const getSeverityBand = (risk: number) => {
    if (risk >= 80) return 'CRITICAL';
    if (risk >= 65) return 'HIGH';
    if (risk >= 45) return 'MEDIUM';
    return 'LOW';
  };

  const getStatusBadge = (status: string, isOnline: boolean) => {
    switch (status) {
      case 'Healthy':
        return (
          <span className="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-950/60 text-emerald-400 border border-emerald-500/40">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            <span>Healthy</span>
          </span>
        );
      case 'Suspicious':
        return (
          <span className="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-950/60 text-amber-400 border border-amber-500/40">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
            <span>Suspicious</span>
          </span>
        );
      case 'Compromised':
        return (
          <span className="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-rose-950/80 text-rose-300 border border-rose-500/60 animate-pulse">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-400 animate-ping" />
            <span>Compromised</span>
          </span>
        );
      case 'Isolated':
        return (
          <span className="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-purple-950/60 text-purple-300 border border-purple-500/40">
            <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
            <span>Isolated</span>
          </span>
        );
      case 'Remediated':
        return (
          <span className="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-cyan-950/60 text-cyan-300 border border-cyan-500/40">
            <CheckCircle2 className="w-3 h-3 text-cyan-400" />
            <span>Remediated</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-800 text-slate-400 border border-slate-700">
            <span className="w-1.5 h-1.5 rounded-full bg-slate-500" />
            <span>Offline</span>
          </span>
        );
    }
  };

  const getRiskBadge = (risk: number) => {
    const band = getSeverityBand(risk);
    switch (band) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-rose-950 text-rose-400 border border-rose-800">{risk} CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-amber-950 text-amber-400 border border-amber-800">{risk} HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-yellow-950 text-yellow-400 border border-yellow-800">{risk} MEDIUM</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">{risk} LOW</span>;
    }
  };

  // Filter devices
  const filteredDevices = devices.filter((d: any) => {
    const matchesSearch =
      d.hostname.toLowerCase().includes(searchTerm.toLowerCase()) ||
      d.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (d.user_name && d.user_name.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (d.user_email && d.user_email.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesStatus = statusFilter === 'ALL' || d.status === statusFilter;
    const matchesSeverity = severityFilter === 'ALL' || getSeverityBand(d.risk) === severityFilter;

    return matchesSearch && matchesStatus && matchesSeverity;
  });

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 max-w-7xl mx-auto">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center space-x-2.5">
            <div className="p-2 bg-cyan-950/60 border border-cyan-800/60 rounded-lg text-cyan-400">
              <Laptop className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl sm:text-2xl font-bold tracking-wide text-slate-100 flex items-center space-x-2">
                <span>Managed Endpoints</span>
                <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-mono">
                  {activeOrg?.name || 'Bank A'}
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-0.5">
                Real-time workstation fleet monitoring, anomaly heuristics, and administrative remote remediation.
              </p>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => fetchDevices()}
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-cyan-500/50 text-slate-300 hover:text-cyan-400 transition-colors"
            title="Refresh Fleet Telemetry"
          >
            <RefreshCw className="w-4 h-4" />
          </button>

          <button
            onClick={handleRunEndpointDemo}
            disabled={runningDemo}
            className="flex items-center space-x-1.5 px-3 py-2 bg-gradient-to-r from-amber-500 to-orange-600 hover:from-amber-400 hover:to-orange-500 text-slate-950 text-xs font-bold rounded-lg shadow-lg shadow-amber-500/20 transition-all disabled:opacity-50"
            title="Scripted 4-step Attack & Remediation Demo Narrative"
          >
            <Sparkles className="w-3.5 h-3.5 animate-spin-slow" />
            <span>{runningDemo ? 'Simulating Narrative...' : 'Run Endpoint Demo'}</span>
          </button>

          <button
            onClick={handleResetEndpointDemo}
            disabled={resettingDemo}
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-amber-500/50 text-slate-400 hover:text-amber-300 transition-colors"
            title="Reset Endpoint Demo to Clean Baseline"
          >
            <RotateCcw className={`w-4 h-4 ${resettingDemo ? 'animate-spin' : ''}`} />
          </button>

          <button
            onClick={() => {
              setEnrollmentCode(null);
              setIsEnrollModalOpen(true);
            }}
            className="flex items-center space-x-2 px-3.5 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 text-xs font-semibold rounded-lg shadow-lg shadow-cyan-500/20 transition-all"
          >
            <Plus className="w-4 h-4" />
            <span>Enroll Workstation</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-12 gap-3 bg-[#0F1420] p-3.5 rounded-xl border border-slate-800">
        <div className="sm:col-span-5 relative">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by hostname, device ID, user name or email..."
            className="w-full bg-[#0B0F17] border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="sm:col-span-4 flex items-center space-x-2">
          <Filter className="w-3.5 h-3.5 text-slate-500 shrink-0" />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="w-full bg-[#0B0F17] border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Statuses</option>
            <option value="Healthy">Healthy</option>
            <option value="Suspicious">Suspicious</option>
            <option value="Compromised">Compromised</option>
            <option value="Isolated">Isolated</option>
            <option value="Remediated">Remediated</option>
            <option value="Offline">Offline</option>
          </select>
        </div>

        <div className="sm:col-span-3">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="w-full bg-[#0B0F17] border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Risk Bands</option>
            <option value="CRITICAL">Critical Risk (≥ 80)</option>
            <option value="HIGH">High Risk (≥ 65)</option>
            <option value="MEDIUM">Medium Risk (≥ 45)</option>
            <option value="LOW">Low Risk (&lt; 45)</option>
          </select>
        </div>
      </div>

      {/* Fleet Overview Metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-[#0F1420] border border-slate-800 rounded-xl p-4">
          <span className="text-xs text-slate-400 font-mono">Total Workstations</span>
          <div className="text-2xl font-bold text-slate-100 mt-1">{devices.length}</div>
          <span className="text-[10px] text-slate-500">Enrolled in defense mesh</span>
        </div>
        <div className="bg-[#0F1420] border border-slate-800 rounded-xl p-4">
          <span className="text-xs text-emerald-400 font-mono">Active / Healthy</span>
          <div className="text-2xl font-bold text-emerald-400 mt-1">
            {devices.filter((d: any) => d.status === 'Healthy' || d.status === 'Remediated').length}
          </div>
          <span className="text-[10px] text-slate-500">Normal operating posture</span>
        </div>
        <div className="bg-[#0F1420] border border-slate-800 rounded-xl p-4">
          <span className="text-xs text-rose-400 font-mono">Compromised / Under Attack</span>
          <div className="text-2xl font-bold text-rose-400 mt-1">
            {devices.filter((d: any) => d.status === 'Compromised' || d.status === 'Suspicious').length}
          </div>
          <span className="text-[10px] text-slate-500">Requires SOC remediation</span>
        </div>
        <div className="bg-[#0F1420] border border-slate-800 rounded-xl p-4">
          <span className="text-xs text-purple-400 font-mono">Simulated Isolated</span>
          <div className="text-2xl font-bold text-purple-400 mt-1">
            {devices.filter((d: any) => d.status === 'Isolated').length}
          </div>
          <span className="text-[10px] text-slate-500">Traffic dropped in mesh</span>
        </div>
      </div>

      {/* Endpoints Table */}
      <div className="bg-[#0F1420] border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/60 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                <th className="py-3.5 px-4">Workstation</th>
                <th className="py-3.5 px-4">Assigned User</th>
                <th className="py-3.5 px-4">Status</th>
                <th className="py-3.5 px-4">Risk Exposure</th>
                <th className="py-3.5 px-4">Heartbeat / Last Seen</th>
                <th className="py-3.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 text-xs text-slate-300">
              {filteredDevices.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500 italic">
                    No endpoint devices match the selected filters.
                  </td>
                </tr>
              ) : (
                filteredDevices.map((d: any) => (
                  <tr
                    key={d.id}
                    className="hover:bg-slate-800/30 transition-colors cursor-pointer group"
                    onClick={() => navigate(`/endpoints/${d.id}`)}
                  >
                    <td className="py-3 px-4">
                      <div className="flex items-center space-x-3">
                        <div className={`p-2 rounded-lg ${
                          d.status === 'Compromised' ? 'bg-rose-950/60 text-rose-400 border border-rose-800/60' :
                          d.status === 'Suspicious' ? 'bg-amber-950/60 text-amber-400 border border-amber-800/60' :
                          'bg-slate-800 text-cyan-400'
                        }`}>
                          <Laptop className="w-4 h-4" />
                        </div>
                        <div>
                          <span className="font-semibold text-slate-100 group-hover:text-cyan-400 transition-colors block">
                            {d.hostname}
                          </span>
                          <span className="text-[10px] font-mono text-slate-500 block">
                            {d.id} • {d.os}
                          </span>
                        </div>
                      </div>
                    </td>

                    <td className="py-3 px-4">
                      <div className="flex items-center space-x-1.5">
                        <User className="w-3.5 h-3.5 text-slate-500" />
                        <div>
                          <span className="font-medium text-slate-200 block">{d.user_name || 'Assigned User'}</span>
                          <span className="text-[10px] text-slate-500 block truncate">{d.user_email || 'user@org.com'}</span>
                        </div>
                      </div>
                    </td>

                    <td className="py-3 px-4">
                      {getStatusBadge(d.status, d.isOnline)}
                    </td>

                    <td className="py-3 px-4">
                      {getRiskBadge(d.risk)}
                    </td>

                    <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">
                      <div className="flex items-center space-x-1.5">
                        <span className={`w-2 h-2 rounded-full ${d.isOnline ? 'bg-emerald-400 animate-ping' : 'bg-slate-600'}`} />
                        <span>{new Date(d.last_seen).toLocaleTimeString()}</span>
                      </div>
                    </td>

                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          navigate(`/endpoints/${d.id}`);
                        }}
                        className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-cyan-950 border border-slate-700 hover:border-cyan-500/50 text-cyan-300 text-xs font-medium transition-all inline-flex items-center space-x-1.5"
                      >
                        <span>Inspect</span>
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal: Enroll New Workstation */}
      {isEnrollModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0F1420] border border-slate-800 rounded-2xl p-6 max-w-md w-full shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
                <Laptop className="w-4 h-4 text-cyan-400" />
                <span>Enroll New Workstation</span>
              </h3>
              <button
                onClick={() => setIsEnrollModalOpen(false)}
                className="text-slate-500 hover:text-slate-300 text-sm"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-slate-400">
              Generate a one-time enrollment authorization code for an employee workstation in {activeOrg?.name}.
            </p>

            {!enrollmentCode ? (
              <form onSubmit={handleGenerateCode} className="space-y-4">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Target User ID / Email</label>
                  <input
                    type="text"
                    value={enrollTargetUser}
                    onChange={(e) => setEnrollTargetUser(e.target.value)}
                    placeholder="e.g. usr-bank-alice or leave blank"
                    className="w-full bg-[#0B0F17] border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                  <span className="text-[10px] text-slate-500 mt-1 block">
                    Defaults to current admin account if omitted.
                  </span>
                </div>

                <div className="flex justify-end space-x-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setIsEnrollModalOpen(false)}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 text-xs font-medium"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={generatingCode}
                    className="px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 text-xs font-semibold shadow-md"
                  >
                    {generatingCode ? 'Generating...' : 'Generate Code'}
                  </button>
                </div>
              </form>
            ) : (
              <div className="space-y-4">
                <div className="p-3 bg-[#0B0F17] border border-cyan-800/60 rounded-xl space-y-2">
                  <span className="text-[10px] text-slate-400 uppercase font-mono block">One-Time Enrollment Code:</span>
                  <div className="flex items-center justify-between">
                    <span className="text-lg font-mono font-bold text-cyan-400">{enrollmentCode}</span>
                    <button
                      onClick={() => copyToClipboard(enrollmentCode)}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 flex items-center space-x-1"
                    >
                      {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copied ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <span className="text-[10px] text-amber-400/80 block">Valid for 2 hours. Single-use only.</span>
                </div>

                <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800 text-[11px] font-mono text-slate-400 space-y-1">
                  <p className="font-semibold text-slate-300">Run on employee workstation:</p>
                  <p className="text-cyan-300 select-all">npm --prefix agent run enroll -- {enrollmentCode}</p>
                </div>

                <button
                  type="button"
                  onClick={() => setIsEnrollModalOpen(false)}
                  className="w-full py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium transition-colors"
                >
                  Done
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

