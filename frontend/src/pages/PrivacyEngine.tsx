import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  EyeOff,
  Sparkles,
  Lock,
  ArrowRight,
  CheckCircle2,
  Share2,
  FileCode,
  ShieldCheck,
  Check,
  ExternalLink,
  ShieldAlert,
  XCircle,
  Binary,
  Layers,
  Database
} from 'lucide-react';
import { useApp } from '../context/AppContext';

export const PrivacyEngine: React.FC = () => {
  const { incidents, sanitizePrivacyPattern, addNotification, activeOrg } = useApp();
  const navigate = useNavigate();

  // Filter incidents to only show current org's incidents
  const orgIncidents = React.useMemo(() => {
    if (!activeOrg) return incidents;
    return incidents.filter((i) => i.orgId === activeOrg.id);
  }, [incidents, activeOrg]);

  const [selectedIncId, setSelectedIncId] = useState<string>(orgIncidents[0]?.id || 'inc-1');
  const [isProcessing, setIsProcessing] = useState(false);
  const [result, setResult] = useState<any>(null);

  // Reset selected incident when org changes
  React.useEffect(() => {
    setSelectedIncId(orgIncidents[0]?.id || '');
    setResult(null);
  }, [activeOrg?.id]);

  const [maskState, setMaskState] = useState({
    employee: true,
    ip: true,
    device: true,
    account: true,
    payload: true
  });

  const activeIncident = orgIncidents.find((i) => i.id === selectedIncId) || orgIncidents[0] || incidents[0];

  const handleSanitize = async () => {
    if (!activeIncident) return;
    setIsProcessing(true);
    const res = await sanitizePrivacyPattern(activeIncident.id);
    setResult(res);
    setIsProcessing(false);
  };

  const handleViewInLedger = () => {
    navigate('/dlt-ledger');
  };

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 sm:space-y-8 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-100 uppercase">
              PRIVACY & ANONYMIZATION ENGINE
            </h1>
            <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 text-[10px] font-mono border border-cyan-800 font-bold">
              ZERO-PII SHARING
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Zero-knowledge privacy engine transforming sensitive PII incident logs into shareable, cryptographically hashed behavioral threat patterns.
          </p>
        </div>

        <button
          onClick={handleSanitize}
          disabled={isProcessing}
          className="flex items-center space-x-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs shadow-lg glow-cyan transition-all"
        >
          <Sparkles className={`w-4 h-4 ${isProcessing ? 'animate-spin' : ''}`} />
          <span>{isProcessing ? 'SANITIZING LOGS...' : 'GENERATE SHAREABLE PATTERN'}</span>
        </button>
      </div>

      {/* DEDICATED "SHARED vs NOT SHARED" COMPREHENSIVE PRIVACY PANEL */}
      <div className="glass-panel p-6 rounded-2xl border border-cyan-500/40 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div>
            <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider flex items-center space-x-2">
              <EyeOff className="w-4 h-4 text-cyan-400" />
              <span>CONFIDENTIALITY AUDIT MATRIX: WHAT IS SHARED vs. WHAT IS NEVER SHARED</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Strict mathematical guarantees ensuring zero internal reconnaissance data leaks onto the decentralized mesh.
            </p>
          </div>
          <span className="text-xs font-mono px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-emerald-400 font-bold">
            ✓ ZERO PII EXPOSURE
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
          {/* NEVER SHARED COLUMN */}
          <div className="p-4 rounded-xl bg-rose-950/20 border border-rose-800/80 space-y-3">
            <div className="flex items-center space-x-2 text-rose-400 font-bold uppercase tracking-wider text-xs border-b border-rose-900/60 pb-2">
              <XCircle className="w-4 h-4 text-rose-500 shrink-0" />
              <span>NEVER SHARED / STRIPPED AT SOURCE</span>
            </div>

            <ul className="space-y-2 text-slate-300">
              <li className="flex items-start space-x-2">
                <span className="text-rose-400 font-bold">✕</span>
                <div>
                  <strong className="text-slate-100">Employee PII:</strong> Names, employee IDs, email addresses, department titles.
                </div>
              </li>
              <li className="flex items-start space-x-2">
                <span className="text-rose-400 font-bold">✕</span>
                <div>
                  <strong className="text-slate-100">Internal IP & Topology:</strong> Private subnets (10.0.X.X, 192.168.X.X), server hostnames, VLAN tags.
                </div>
              </li>
              <li className="flex items-start space-x-2">
                <span className="text-rose-400 font-bold">✕</span>
                <div>
                  <strong className="text-slate-100">Device Hardware Identifiers:</strong> MAC addresses, hardware UUIDs (DEV-83921), serial keys.
                </div>
              </li>
              <li className="flex items-start space-x-2">
                <span className="text-rose-400 font-bold">✕</span>
                <div>
                  <strong className="text-slate-100">Raw Incident Payloads:</strong> Corporate database queries, file contents, secret tokens, credentials.
                </div>
              </li>
            </ul>
          </div>

          {/* SAFELY SHARED COLUMN */}
          <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-800/80 space-y-3">
            <div className="flex items-center space-x-2 text-emerald-400 font-bold uppercase tracking-wider text-xs border-b border-emerald-900/60 pb-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>SAFELY SHARED TO DEFENSE MESH</span>
            </div>

            <ul className="space-y-2 text-slate-300">
              <li className="flex items-start space-x-2">
                <span className="text-emerald-400 font-bold">✓</span>
                <div>
                  <strong className="text-slate-100">Normalized TTP Sequence:</strong> Abstracted MITRE event transitions (e.g. FAILED_LOGIN → PRIV_ESC).
                </div>
              </li>
              <li className="flex items-start space-x-2">
                <span className="text-emerald-400 font-bold">✓</span>
                <div>
                  <strong className="text-slate-100">Cryptographic SHA-256 Hash:</strong> Deterministic proof committed to DLT Ledger (e.g. Block #10421).
                </div>
              </li>
              <li className="flex items-start space-x-2">
                <span className="text-emerald-400 font-bold">✓</span>
                <div>
                  <strong className="text-slate-100">Severity & Confidence Ratings:</strong> High-level classification scores without internal contextual metadata.
                </div>
              </li>
              <li className="flex items-start space-x-2">
                <span className="text-emerald-400 font-bold">✓</span>
                <div>
                  <strong className="text-slate-100">Differential Privacy Noise:</strong> Mathematical perturbation preventing frequency reconstruction attacks.
                </div>
              </li>
            </ul>
          </div>
        </div>
      </div>

      {/* Select Incident & Interactive Masking Options */}
      <div className="glass-panel p-5 rounded-2xl border border-slate-800 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex-1">
            <label className="block text-[10px] font-mono text-slate-400 uppercase mb-1">Select Incident to Sanitize</label>
            <select
              value={selectedIncId}
              onChange={(e) => setSelectedIncId(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500"
            >
              {orgIncidents.map((inc) => (
                <option key={inc.id} value={inc.id}>
                  {inc.incidentId} — {inc.title} ({inc.severity})
                </option>
              ))}
            </select>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 text-xs font-mono">
            <span className="text-slate-400">Mask Fields:</span>
            {Object.keys(maskState).map((key) => (
              <label key={key} className="flex items-center space-x-1.5 cursor-pointer bg-slate-900 px-2.5 py-1 rounded border border-slate-800">
                <input
                  type="checkbox"
                  checked={(maskState as any)[key]}
                  onChange={(e) => setMaskState({ ...maskState, [key]: e.target.checked })}
                  className="accent-cyan-500"
                />
                <span className="capitalize text-slate-300">{key}</span>
              </label>
            ))}
          </div>
        </div>
      </div>

      {/* Side-by-Side Comparison Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Private Incident Data */}
        <div className="glass-panel p-6 rounded-2xl border border-rose-500/30 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center space-x-2 text-rose-400 font-bold text-xs uppercase">
              <Lock className="w-4 h-4" />
              <span>ORIGINAL PRIVATE TELEMETRY (CONFIDENTIAL)</span>
            </div>
            <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-400 text-[10px] font-mono border border-rose-800">
              INTERNAL ONLY
            </span>
          </div>

          <div className="space-y-3 font-mono text-xs">
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
              <div className="text-[10px] text-slate-500 uppercase">Employee Name</div>
              <div className="text-slate-200 font-semibold mt-0.5">
                {maskState.employee ? '•••••••••• [MASKED PII]' : activeIncident?.rawLogs?.employee || 'John Doe'}
              </div>
            </div>

            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
              <div className="text-[10px] text-slate-500 uppercase">Internal IP Address</div>
              <div className="text-slate-200 font-semibold mt-0.5">
                {maskState.ip ? '10.0.X.X [INTERNAL SUBNET]' : activeIncident?.rawLogs?.internalIp || '10.0.4.21'}
              </div>
            </div>

            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
              <div className="text-[10px] text-slate-500 uppercase">Hardware Device ID</div>
              <div className="text-slate-200 font-semibold mt-0.5">
                {maskState.device ? 'DEV-XXXXX [HARDWARE SERIAL]' : activeIncident?.rawLogs?.deviceId || 'DEV-83921'}
              </div>
            </div>

            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
              <div className="text-[10px] text-slate-500 uppercase">Target Account</div>
              <div className="text-slate-200 font-semibold mt-0.5">
                {maskState.account ? 'user@domain.anon [ANONYMIZED]' : activeIncident?.rawLogs?.account || 'admin@demobank.com'}
              </div>
            </div>

            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
              <div className="text-[10px] text-slate-500 uppercase">Raw Log Excerpt</div>
              <pre className="text-[10px] text-slate-400 whitespace-pre-wrap mt-1">
                {maskState.payload
                  ? 'TIMESTAMP=2026-09-04T09:42:15Z SRC=[REDACTED] USER=[REDACTED] DEV=[REDACTED] EVENT=FAILED_LOGIN ATTEMPTS=15 STATUS=DENIED; ROLE_CHANGE=SUPERADMIN PRIVILEGE=ELEVATED EXFIL_BYTES=[REDACTED]'
                  : activeIncident?.rawLogs?.rawLogText || 'RAW_LOG_DATA_EXFILTRATION'}
              </pre>
            </div>
          </div>
        </div>

        {/* Right: Privacy-Safe Threat Pattern */}
        <div className="glass-panel p-6 rounded-2xl border border-cyan-500/40 bg-gradient-to-br from-slate-900 via-slate-900 to-cyan-950/20 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center space-x-2 text-cyan-400 font-bold text-xs uppercase">
              <ShieldCheck className="w-4 h-4" />
              <span>SANITIZED SHAREABLE THREAT PATTERN</span>
            </div>
            <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 text-[10px] font-mono border border-cyan-800">
              SHAREABLE INTEL
            </span>
          </div>

          <div className="space-y-4">
            <div>
              <div className="text-[10px] font-mono text-slate-500 uppercase">Threat Pattern ID</div>
              <div className="text-lg font-black font-mono text-cyan-400">
                {result?.sanitizationResult?.sanitizedPattern?.threatPatternId || 'TH-7821'}
              </div>
            </div>

            <div>
              <div className="text-[10px] font-mono text-slate-500 uppercase">SHA-256 Cryptographic Pattern Hash</div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-[11px] font-mono text-cyan-300 break-all">
                {result?.sanitizationResult?.sanitizedPattern?.patternHash ||
                  'a8f3b29c91d4e5f670123456789abcdef0123456789abcdef0123456789ab2bd'}
              </div>
            </div>

            <div>
              <div className="text-[10px] font-mono text-slate-500 uppercase mb-2">Anonymized Behavior Sequence</div>
              <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                {['FAILED_LOGIN', 'SUCCESSFUL_LOGIN', 'NEW_DEVICE', 'PRIVILEGE_ESCALATION', 'LARGE_DATA_TRANSFER'].map(
                  (step, idx) => (
                    <React.Fragment key={idx}>
                      <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-200">
                        {step}
                      </span>
                      {idx < 4 && <ArrowRight className="w-3.5 h-3.5 text-cyan-400" />}
                    </React.Fragment>
                  )
                )}
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-cyan-950/40 border border-cyan-800/60 text-xs text-slate-300 space-y-2 font-mono">
              <div className="font-bold text-cyan-400">Mathematical Privacy Audit Guarantee:</div>
              <p className="text-[11px] leading-relaxed">
                All PII identifiers, internal IP ranges, device fingerprints, and corporate credentials have been stripped.
              </p>
              {result && (
                <button
                  onClick={handleViewInLedger}
                  className="w-full py-2.5 mt-1 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center justify-center space-x-1.5 glow-cyan transition-all"
                >
                  <span>Inspect Pattern on DLT Ledger</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
