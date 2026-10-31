import React, { useState, useEffect } from 'react';
import {
  Laptop,
  ShieldCheck,
  AlertTriangle,
  Lock,
  RefreshCw,
  Activity,
  History,
  CheckCircle2,
  Terminal,
  Clock,
  ShieldAlert,
  Flame,
  Info
} from 'lucide-react';
import { useApp } from '../context/AppContext';

export const MyDevice: React.FC = () => {
  const { currentUser, token, resetPassword, addNotification } = useApp();
  const [deviceData, setDeviceData] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [simulating, setSimulating] = useState<boolean>(false);
  const [newPassword, setNewPassword] = useState('');
  const [resetError, setResetError] = useState<string | null>(null);
  const [resetSuccess, setResetSuccess] = useState<boolean>(false);

  const fetchMyDevice = async () => {
    if (!token) return;
    try {
      setLoading(true);
      const res = await fetch('/api/devices/my-device', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setDeviceData(data);
      }
    } catch (err) {
      console.error('Error loading my device:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMyDevice();
    const interval = setInterval(fetchMyDevice, 5000);
    return () => clearInterval(interval);
  }, [token]);

  const handlePasswordReset = async (e: React.FormEvent) => {
    e.preventDefault();
    setResetError(null);
    if (newPassword.length < 8) {
      setResetError('Password must be at least 8 characters long');
      return;
    }
    const res = await resetPassword(newPassword);
    if (res.success) {
      setResetSuccess(true);
      setNewPassword('');
      fetchMyDevice();
    } else {
      setResetError(res.error || 'Password update failed');
    }
  };

  const handleSimulateAttack = async () => {
    if (!deviceData?.device?.id) return;
    try {
      setSimulating(true);
      const res = await fetch('/api/telemetry/simulate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({
          eventType: 'FAILED_LOGIN',
          details: `Simulated attack launched from user client on device ${deviceData.device.id}.`
        })
      });
      if (res.ok) {
        addNotification(
          'Simulated Attack Triggered',
          `Injected suspicious telemetry sequence on ${deviceData.device.hostname}. Check SOC admin alerts!`,
          'ALERT'
        );
        fetchMyDevice();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setSimulating(false);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'Healthy':
        return <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-950/60 text-emerald-400 border border-emerald-500/40">Healthy</span>;
      case 'Suspicious':
        return <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-950/60 text-amber-400 border border-amber-500/40">Suspicious</span>;
      case 'Compromised':
        return <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-rose-950/60 text-rose-400 border border-rose-500/40 animate-pulse">Compromised</span>;
      case 'Isolated':
        return <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-purple-950/60 text-purple-400 border border-purple-500/40">Simulated Isolation</span>;
      case 'Remediated':
        return <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-cyan-950/60 text-cyan-400 border border-cyan-500/40">Remediated</span>;
      default:
        return <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700">Offline</span>;
    }
  };

  const getRiskBadge = (risk: number) => {
    if (risk >= 80) return <span className="text-rose-400 font-bold">Critical ({risk}/100)</span>;
    if (risk >= 65) return <span className="text-amber-400 font-bold">High ({risk}/100)</span>;
    if (risk >= 45) return <span className="text-yellow-400 font-bold">Medium ({risk}/100)</span>;
    return <span className="text-emerald-400 font-bold">Low ({risk}/100)</span>;
  };

  if (loading && !deviceData) {
    return (
      <div className="p-8 flex items-center justify-center text-slate-400">
        <RefreshCw className="w-6 h-6 animate-spin mr-3 text-cyan-400" />
        <span>Loading endpoint telemetry & agent state...</span>
      </div>
    );
  }

  const device = deviceData?.device;
  const recentNotices = deviceData?.recentNotices || [];
  const recentEvents = deviceData?.recentEvents || [];
  const mustReset = currentUser?.mustReset || deviceData?.mustResetPassword;

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 max-w-5xl mx-auto">
      {/* 1. Mandatory Consent & Visibility Banner */}
      <div className="bg-[#0F1420] border-l-4 border-cyan-400 rounded-xl p-4 sm:p-5 shadow-lg flex items-start justify-between">
        <div className="flex items-start space-x-3.5">
          <div className="p-2.5 bg-cyan-950/60 border border-cyan-800/60 rounded-lg text-cyan-400 shrink-0">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-sm sm:text-base font-bold text-slate-100">
                CyberGuard Endpoint Agent Active
              </h2>
              <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-mono">
                MONITORED BY {currentUser?.orgId?.toUpperCase()}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              This system is registered in the institutional cybersecurity mesh. All remote remediation commands require administrator HMAC signatures and are logged to an immutable hash chain.
            </p>
          </div>
        </div>
        <div className="hidden sm:flex items-center space-x-1.5 text-xs text-emerald-400 bg-emerald-950/30 px-2.5 py-1 rounded-full border border-emerald-500/30">
          <div className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
          <span>Agent Live</span>
        </div>
      </div>

      {/* 2. Password Reset Required Notice (if flagged by admin reset_credentials) */}
      {mustReset && (
        <div className="bg-rose-950/40 border border-rose-500/60 rounded-xl p-5 shadow-lg">
          <div className="flex items-center space-x-2 text-rose-400 mb-2">
            <ShieldAlert className="w-5 h-5 shrink-0" />
            <h3 className="text-sm font-bold uppercase tracking-wider">Mandatory Credential Reset Required</h3>
          </div>
          <p className="text-xs text-slate-300 mb-4">
            An administrator initiated a credential reset on your account following a security detection. You must set a new secure password to restore full access.
          </p>

          {resetSuccess ? (
            <div className="p-3 bg-emerald-950/50 border border-emerald-500/40 rounded-lg text-emerald-300 text-xs flex items-center space-x-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>Password successfully updated! Your access is now secure.</span>
            </div>
          ) : (
            <form onSubmit={handlePasswordReset} className="flex flex-col sm:flex-row items-center space-y-2 sm:space-y-0 sm:space-x-3">
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="Enter new secure password (min 8 chars)"
                className="w-full sm:w-80 bg-[#0B0F17] border border-slate-700 rounded-lg px-3.5 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-rose-400"
              />
              <button
                type="submit"
                className="w-full sm:w-auto px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold rounded-lg shadow-md transition-all"
              >
                Update Password
              </button>
              {resetError && <span className="text-xs text-rose-400">{resetError}</span>}
            </form>
          )}
        </div>
      )}

      {/* 3. Device Summary Card */}
      {device ? (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {/* Main Card */}
          <div className="md:col-span-2 bg-[#0F1420] border border-slate-800 rounded-xl p-5 shadow-md space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
              <div className="flex items-center space-x-3">
                <div className="p-2 rounded-lg bg-slate-800 text-cyan-400">
                  <Laptop className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-slate-100">{device.hostname}</h3>
                  <p className="text-xs font-mono text-slate-400">{device.id} • {device.os}</p>
                </div>
              </div>
              <div>{getStatusBadge(device.status)}</div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
              <div className="bg-[#0B0F17] p-3 rounded-lg border border-slate-800/60">
                <span className="text-slate-400 block mb-1">Assigned User</span>
                <span className="font-semibold text-slate-200">{currentUser?.name}</span>
                <span className="text-[10px] text-slate-500 block truncate">{currentUser?.email}</span>
              </div>
              <div className="bg-[#0B0F17] p-3 rounded-lg border border-slate-800/60">
                <span className="text-slate-400 block mb-1">Device Risk Index</span>
                <div className="text-sm">{getRiskBadge(device.risk)}</div>
                <span className="text-[10px] text-slate-500 block">Calculated via RiskEngine</span>
              </div>
              <div className="bg-[#0B0F17] p-3 rounded-lg border border-slate-800/60">
                <span className="text-slate-400 block mb-1">Last Telemetry Beat</span>
                <span className="font-semibold text-slate-200">
                  {new Date(device.last_seen).toLocaleTimeString()}
                </span>
                <span className="text-[10px] text-slate-500 block">WebSocket Connected</span>
              </div>
            </div>

            {/* Harmless Attack Simulation (Demo Prototype Only) */}
            <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between">
              <div className="flex items-center space-x-2 text-xs text-slate-400">
                <Flame className="w-4 h-4 text-amber-400" />
                <span>Simulate suspicious endpoint activity (harmless prototype demo):</span>
              </div>
              <button
                type="button"
                onClick={handleSimulateAttack}
                disabled={simulating}
                className="px-3 py-1.5 bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-amber-300 rounded-lg text-xs font-medium transition-all flex items-center space-x-1.5"
              >
                <span>{simulating ? 'Injecting...' : 'Simulate Attack'}</span>
              </button>
            </div>
          </div>

          {/* Admin Remediation Notices Feed */}
          <div className="bg-[#0F1420] border border-slate-800 rounded-xl p-5 shadow-md flex flex-col">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3 flex items-center space-x-1.5">
              <History className="w-4 h-4 text-cyan-400" />
              <span>Remediation Notices</span>
            </h3>

            {recentNotices.length === 0 ? (
              <div className="flex-1 flex flex-col items-center justify-center text-center p-4 text-slate-500 text-xs">
                <ShieldCheck className="w-8 h-8 text-emerald-400/40 mb-2" />
                <span>No administrative remediation actions have been taken on this system.</span>
              </div>
            ) : (
              <div className="space-y-2.5 overflow-y-auto max-h-60 pr-1">
                {recentNotices.map((n: any) => (
                  <div key={n.commandId} className="p-2.5 bg-[#0B0F17] border border-slate-800 rounded-lg text-xs space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-cyan-400 font-mono uppercase">{n.action}</span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 font-mono">
                        {n.status}
                      </span>
                    </div>
                    <p className="text-slate-300 text-[11px]">{n.message}</p>
                    <span className="text-[10px] text-slate-500 block">
                      {new Date(n.issuedAt).toLocaleTimeString()}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="bg-[#0F1420] border border-slate-800 rounded-xl p-8 text-center text-slate-400">
          <Laptop className="w-10 h-10 mx-auto text-slate-600 mb-2" />
          <p className="text-sm">No device is currently enrolled for your account.</p>
        </div>
      )}

      {/* 4. Recent Local Event Activity */}
      <div className="bg-[#0F1420] border border-slate-800 rounded-xl p-5 shadow-md">
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3 flex items-center space-x-1.5">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span>Endpoint Event Buffer (Simulated Diagnostics)</span>
        </h3>
        {recentEvents.length === 0 ? (
          <p className="text-xs text-slate-500 italic">No suspicious events logged in current buffer.</p>
        ) : (
          <div className="divide-y divide-slate-800/80 max-h-64 overflow-y-auto">
            {recentEvents.map((evt: any) => (
              <div key={evt.id} className="py-2.5 flex items-center justify-between text-xs">
                <div className="flex items-center space-x-3">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                    evt.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-400 border border-rose-800' :
                    evt.severity === 'HIGH' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                    'bg-slate-800 text-slate-300'
                  }`}>
                    {evt.event_type}
                  </span>
                  <span className="text-slate-300">{evt.details}</span>
                </div>
                <span className="text-[10px] font-mono text-slate-500 shrink-0 ml-2">
                  {new Date(evt.timestamp).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

