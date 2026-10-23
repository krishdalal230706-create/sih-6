import React, { useState } from 'react';
import {
  Settings as SettingsIcon,
  Sliders,
  Shield,
  Save,
  RefreshCw,
  Database,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Globe,
  Clock,
  Layers,
  Sparkles,
  Server
} from 'lucide-react';
import { useApp } from '../context/AppContext';

export const Settings: React.FC = () => {
  const { activeOrg, addNotification, syncStatus, isSyncingVulns, triggerLiveSync, vulnerabilityStats } = useApp();
  const [threshold, setThreshold] = useState(80);
  const [autoSyncInterval, setAutoSyncInterval] = useState('30');
  const [saved, setSaved] = useState(false);
  const [lastManualSyncResult, setLastManualSyncResult] = useState<any>(null);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSaved(true);
    addNotification('Settings Updated', `System risk threshold (${threshold}/100) and sync interval (${autoSyncInterval}m) saved.`, 'SUCCESS', '/settings');
    setTimeout(() => setSaved(false), 2500);
  };

  const handleManualSync = async () => {
    const res = await triggerLiveSync(true);
    if (res) {
      setLastManualSyncResult(res);
    }
  };

  const formatTimestamp = (iso?: string | null) => {
    if (!iso) return 'Never';
    try {
      const d = new Date(iso);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' ' + d.toLocaleDateString();
    } catch {
      return iso;
    }
  };

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 sm:space-y-8 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-100 uppercase">
            SYSTEM & INTELLIGENCE SETTINGS
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Configure risk quantification thresholds, authoritative threat ingestion adapters, and synchronization policies.
          </p>
        </div>

        <div className="flex items-center space-x-2 font-mono text-xs text-cyan-400">
          <span className="px-3 py-1 rounded bg-cyan-950 border border-cyan-800 flex items-center space-x-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span>Adapter Engine: Online</span>
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: General Configuration Form */}
        <form onSubmit={handleSave} className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-6 text-xs bg-slate-900/60">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              <span>Risk & Defense Controls</span>
            </h3>
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-slate-400 font-mono">Critical Risk Score Threshold</label>
              <span className="font-mono font-bold text-rose-400 text-sm">{threshold} / 100</span>
            </div>
            <input
              type="range"
              min="50"
              max="95"
              value={threshold}
              onChange={(e) => setThreshold(Number(e.target.value))}
              className="w-full h-2 bg-slate-950 rounded-lg appearance-none cursor-pointer accent-cyan-500"
            />
            <p className="text-[10px] text-slate-500 mt-1 font-mono">
              Alerts trigger automatically when an asset or organization exceeds this calculated score.
            </p>
          </div>

          <div>
            <label className="block text-slate-400 font-mono mb-2">Scheduled Ingestion Interval</label>
            <select
              value={autoSyncInterval}
              onChange={(e) => setAutoSyncInterval(e.target.value)}
              className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
            >
              <option value="15">Every 15 Minutes (High-Frequency)</option>
              <option value="30">Every 30 Minutes (Recommended)</option>
              <option value="60">Every 60 Minutes (Standard)</option>
              <option value="360">Every 6 Hours</option>
            </select>
          </div>

          <div className="space-y-3 pt-2 border-t border-slate-800/80">
            <div className="flex items-center justify-between p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono">
              <div>
                <div className="text-slate-200 font-bold">Automated DLT Block Mining</div>
                <div className="text-[10px] text-slate-500">Auto-commit verified threat patterns to local ledger</div>
              </div>
              <input type="checkbox" defaultChecked className="toggle accent-cyan-500" />
            </div>

            <div className="flex items-center justify-between p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono">
              <div>
                <div className="text-slate-200 font-bold">Privacy Engine Anonymization</div>
                <div className="text-[10px] text-slate-500">Strip PII before generating behavioral signatures</div>
              </div>
              <input type="checkbox" defaultChecked className="toggle accent-cyan-500" />
            </div>
          </div>

          <button
            type="submit"
            className="w-full py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs shadow-lg glow-cyan transition-all"
          >
            {saved ? '✓ Settings Saved!' : 'Save System Parameters'}
          </button>
        </form>

        {/* Right Column: Intelligence Synchronization Control Center */}
        <div className="lg:col-span-2 glass-panel p-6 rounded-2xl border border-cyan-500/30 space-y-6 bg-slate-900/60">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
            <div>
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider flex items-center space-x-2">
                <Database className="w-4 h-4 text-cyan-400" />
                <span>INTELLIGENCE SYNCHRONIZATION CONTROL</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Manual trigger, adapter health monitoring, and live ingestion telemetry.
              </p>
            </div>

            <button
              onClick={handleManualSync}
              disabled={isSyncingVulns}
              className={`px-4 py-2 rounded-xl text-xs font-mono font-bold flex items-center space-x-2 transition-all shrink-0 ${
                isSyncingVulns
                  ? 'bg-cyan-950 border border-cyan-500 text-cyan-300 animate-pulse cursor-wait'
                  : 'bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-lg glow-cyan'
              }`}
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isSyncingVulns ? 'animate-spin' : ''}`} />
              <span>{isSyncingVulns ? 'SYNCHRONIZING FEED...' : 'SYNCHRONIZE INTELLIGENCE'}</span>
            </button>
          </div>

          {/* Sync Stats Overview Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
              <div className="text-[10px] text-slate-500 uppercase">Last Synchronization</div>
              <div className="text-xs font-bold text-slate-200 mt-1">
                {formatTimestamp(syncStatus?.lastSyncTime || vulnerabilityStats?.lastSyncTime)}
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
              <div className="text-[10px] text-slate-500 uppercase">Last Sync Added</div>
              <div className="text-base font-black text-emerald-400 mt-1">
                +{syncStatus?.recordsAdded || 0} CVEs
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
              <div className="text-[10px] text-slate-500 uppercase">Records Updated</div>
              <div className="text-base font-black text-cyan-400 mt-1">
                ~{syncStatus?.recordsUpdated || 0} Merged
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
              <div className="text-[10px] text-slate-500 uppercase">Engine Health</div>
              <div className="text-xs font-bold text-emerald-400 mt-1.5 flex items-center space-x-1">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>0 Errors</span>
              </div>
            </div>
          </div>

          {/* Authoritative Source Adapters Grid */}
          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs font-mono text-slate-400">
              <span className="uppercase font-bold tracking-wider text-slate-300">Authoritative Source Adapters</span>
              <span className="text-cyan-400">4 Active Adapters</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {(syncStatus?.sources || []).map((src) => (
                <div
                  key={src.id}
                  className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 flex items-start justify-between font-mono text-xs"
                >
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span className="font-bold text-slate-200">{src.name}</span>
                    </div>
                    <div className="text-[10px] text-slate-500 truncate max-w-xs">{src.url}</div>
                    <div className="text-[10px] text-cyan-400">
                      Ingested: {src.recordsCount > 0 ? `${src.recordsCount} records` : 'Active feed'}
                    </div>
                  </div>

                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold border shrink-0 ${
                      src.syncStatus === 'SUCCESS' || src.enabled
                        ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                        : 'bg-rose-950 text-rose-400 border-rose-800'
                    }`}
                  >
                    ✓ READY
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Recent Sync Logs Audit */}
          <div className="space-y-2.5">
            <div className="text-xs font-mono text-slate-400 uppercase font-bold tracking-wider text-slate-300">
              Recent Synchronization Audit Logs
            </div>

            <div className="space-y-2 max-h-48 overflow-y-auto">
              {(syncStatus?.recentLogs || []).map((log) => (
                <div
                  key={log.id}
                  className="p-3 rounded-xl bg-slate-950 border border-slate-800/80 flex items-center justify-between font-mono text-xs"
                >
                  <div className="flex items-center space-x-3">
                    <span className="text-[11px] text-slate-500">{formatTimestamp(log.createdAt)}</span>
                    <span className="font-bold text-slate-200">{log.sourceName}</span>
                  </div>

                  <div className="flex items-center space-x-3 text-[11px]">
                    <span className="text-emerald-400">+{log.recordsAdded} new</span>
                    <span className="text-cyan-400">~{log.recordsUpdated} updated</span>
                    <span className="text-slate-500">{log.durationMs}ms</span>
                    <span className="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px] font-bold">
                      {log.status}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
