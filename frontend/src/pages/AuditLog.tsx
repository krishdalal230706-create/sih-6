import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  ScrollText,
  ShieldCheck,
  ShieldAlert,
  Search,
  Filter,
  RefreshCw,
  ExternalLink,
  Lock,
  Link as LinkIcon,
  Copy,
  Check,
  AlertTriangle,
  Database,
  Laptop,
  CheckCircle2,
  XCircle,
  Clock,
  ArrowRight
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import { AuditLogRecord } from '../types';

export const AuditLog: React.FC = () => {
  const { token, activeOrg, addNotification } = useApp();

  const [records, setRecords] = useState<AuditLogRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [deviceFilter, setDeviceFilter] = useState('ALL');

  // Chain Verification State
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<{
    isVerified: boolean;
    brokenId: string | null;
    totalVerified: number;
    details: string;
  } | null>(null);

  // DLT Anchor State
  const [anchoring, setAnchoring] = useState(false);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const fetchAuditLogs = async () => {
    if (!token) return;
    try {
      setLoading(true);
      const res = await fetch('/api/audit', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setRecords(data.records || []);
      }
    } catch (err) {
      console.error('Failed to load audit logs:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyChain = async () => {
    if (!token) return;
    setVerifying(true);
    try {
      const res = await fetch('/api/audit/verify', {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await res.json();
      setVerificationResult(data);

      if (data.isVerified) {
        addNotification(
          'Audit Chain Verified',
          `Verified cryptographic SHA-256 integrity across ${data.totalVerified} records. Zero tampering detected.`,
          'SUCCESS'
        );
      } else {
        addNotification(
          'Tamper Detected in Audit Chain',
          `Cryptographic integrity breach detected at record #${data.brokenId}!`,
          'ALERT'
        );
      }
    } catch (err: any) {
      alert('Verification request failed: ' + err.message);
    } finally {
      setVerifying(false);
    }
  };

  const handleTamperRecord = async () => {
    if (!token) return;
    if (!confirm('DEMO ACTION: Intentionally modify a log record in SQLite to demonstrate instant cryptographic detection of tampering?')) {
      return;
    }

    try {
      const res = await fetch('/api/audit/tamper', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({})
      });
      const data = await res.json();

      if (res.ok) {
        addNotification(
          'Adversarial Tamper Injected (Demo)',
          `Modified payload of record #${data.tamperedId}. Run "Verify Chain" to observe detection!`,
          'WARNING'
        );
        await fetchAuditLogs();
        await handleVerifyChain();
      } else {
        alert(data.message || 'Tamper injection failed');
      }
    } catch (err: any) {
      alert(err.message);
    }
  };

  const handleAnchorToDLT = async () => {
    if (!token) return;
    setAnchoring(true);
    try {
      const res = await fetch('/api/audit/anchor-ledger', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        }
      });
      const data = await res.json();

      if (res.ok) {
        addNotification(
          'Anchored to DLT Ledger',
          `Audit root hash anchored into Block #${data.block?.blockNumber}. Validator quorum confirmed.`,
          'SUCCESS',
          '/dlt-ledger'
        );
        fetchAuditLogs();
        handleVerifyChain();
      } else {
        alert(data.message || 'Failed to anchor to DLT');
      }
    } catch (err: any) {
      alert(err.message);
    } finally {
      setAnchoring(false);
    }
  };

  useEffect(() => {
    fetchAuditLogs();
    handleVerifyChain();
  }, [token, activeOrg]);

  const copyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 1500);
  };

  const getActionBadge = (action: string) => {
    if (action.includes('USER_ACCOUNT_LOCKED')) {
      return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-800">ACCT LOCKED</span>;
    }
    if (action.includes('USER_ACCOUNT_UNLOCKED')) {
      return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">ACCT RESTORED</span>;
    }
    if (action.includes('PASSWORD_RESET')) {
      return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950 text-amber-300 border border-amber-800">PWD RESET</span>;
    }
    if (action.includes('MFA_ENFORCED')) {
      return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">MFA POLICY</span>;
    }
    if (action.includes('PERIMETER_ENTITY_BLOCKED')) {
      return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-orange-950 text-orange-300 border border-orange-800">PERIMETER BLOCKED</span>;
    }
    if (action.includes('PRIVILEGE_REVERTED')) {
      return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-yellow-950 text-yellow-300 border border-yellow-800">PRIVILEGE REVERT</span>;
    }
    if (action.includes('USER_SESSIONS_REVOKED')) {
      return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-950 text-purple-300 border border-purple-800">SESSIONS REVOKED</span>;
    }
    if (action.includes('ACCOUNT_ATTACK_DETECTED')) {
      return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-800 animate-pulse">ATTACK ALERT</span>;
    }
    if (action.includes('LOGIN')) {
      return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-950 text-blue-300 border border-blue-800">AUTH</span>;
    }
    if (action.includes('COMMAND_ISSUED')) {
      return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950 text-amber-300 border border-amber-800">CMD ISSUE</span>;
    }
    if (action.includes('COMMAND_RESULT_EXECUTED')) {
      return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">REMEDIATED</span>;
    }
    if (action.includes('ATTACK') || action.includes('ALERT') || action.includes('REJECTED')) {
      return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-800">ALERT</span>;
    }
    if (action.includes('DLT') || action.includes('ANCHOR')) {
      return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-950 text-indigo-300 border border-indigo-800">DLT ANCHOR</span>;
    }
    return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">SYSTEM</span>;
  };

  const uniqueDevices = Array.from(new Set(records.map((r) => r.device_id).filter((id): id is string => Boolean(id))));

  const filteredRecords = records.filter((r) => {
    const matchesSearch =
      r.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      r.actor.toLowerCase().includes(searchTerm.toLowerCase()) ||
      r.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
      r.details.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (r.device_id && r.device_id.toLowerCase().includes(searchTerm.toLowerCase()));

    let matchesAction = false;
    if (actionFilter === 'ALL') {
      matchesAction = true;
    } else if (actionFilter === 'ACCOUNT_ACTIONS') {
      matchesAction =
        r.action.startsWith('USER_') ||
        r.action.startsWith('PASSWORD_') ||
        r.action.startsWith('MFA_') ||
        r.action.startsWith('PERIMETER_') ||
        r.action.startsWith('PRIVILEGE_') ||
        r.action.includes('ACCOUNT');
    } else {
      matchesAction = r.action.includes(actionFilter);
    }

    const matchesDevice = deviceFilter === 'ALL' || r.device_id === deviceFilter;

    return matchesSearch && matchesAction && matchesDevice;
  });

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 max-w-7xl mx-auto">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <span className="text-[10px] font-mono uppercase tracking-wider text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800">
              CRYPTOGRAPHIC INTEGRITY GUARANTEE
            </span>
            <span className="text-xs text-slate-500 font-mono">ORG: {activeOrg?.name}</span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-100 flex items-center space-x-2 mt-1">
            <ScrollText className="w-6 h-6 text-cyan-400" />
            <span>IMMUTABLE AUDIT TRAIL & HASH-CHAIN</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl">
            Cryptographic SHA-256 hash-chained ledger storing every authentication event, threat detection, remote remediation command, and containment transition.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={fetchAuditLogs}
            className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 transition-all"
            title="Refresh Audit Records"
          >
            <RefreshCw className="w-4 h-4" />
          </button>

          <button
            type="button"
            onClick={handleVerifyChain}
            disabled={verifying}
            className="flex items-center space-x-1.5 px-3 py-2 bg-emerald-950 hover:bg-emerald-900 border border-emerald-500/50 text-emerald-300 text-xs font-semibold rounded-lg transition-all"
          >
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>{verifying ? 'Verifying...' : 'Verify Hash-Chain'}</span>
          </button>

          <button
            type="button"
            onClick={handleAnchorToDLT}
            disabled={anchoring}
            className="flex items-center space-x-1.5 px-3 py-2 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-slate-100 text-xs font-semibold rounded-lg shadow-lg shadow-purple-500/20 transition-all"
          >
            <Database className="w-4 h-4" />
            <span>{anchoring ? 'Anchoring...' : 'Anchor Digest to DLT'}</span>
          </button>

          <button
            type="button"
            onClick={handleTamperRecord}
            className="flex items-center space-x-1.5 px-3 py-2 bg-rose-950/60 hover:bg-rose-900/80 border border-rose-600/50 text-rose-300 text-xs font-semibold rounded-lg transition-all"
            title="Demonstrate instant detection of log tampering"
          >
            <AlertTriangle className="w-4 h-4 text-rose-400" />
            <span>Tamper Record (Demo)</span>
          </button>
        </div>
      </div>

      {/* Verification Status Banner */}
      {verificationResult && (
        <div
          className={`p-4 rounded-xl border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 ${
            verificationResult.isVerified
              ? 'bg-emerald-950/30 border-emerald-500/50 text-emerald-300'
              : 'bg-rose-950/40 border-rose-500 text-rose-300 shadow-xl shadow-rose-950/50 animate-pulse'
          }`}
        >
          <div className="flex items-center space-x-3">
            {verificationResult.isVerified ? (
              <CheckCircle2 className="w-6 h-6 text-emerald-400 shrink-0" />
            ) : (
              <XCircle className="w-6 h-6 text-rose-400 shrink-0" />
            )}
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-sm">
                  {verificationResult.isVerified
                    ? 'HASH-CHAIN INTEGRITY VERIFIED'
                    : 'CRYPTOGRAPHIC TAMPER DETECTED!'}
                </span>
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-900 border border-slate-700">
                  {verificationResult.totalVerified} records verified
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-0.5">{verificationResult.details}</p>
            </div>
          </div>

          <div className="flex items-center space-x-2 shrink-0">
            <Link
              to="/dlt-ledger"
              className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold inline-flex items-center space-x-1"
            >
              <span>View DLT Trust Ledger</span>
              <ExternalLink className="w-3 h-3" />
            </Link>
          </div>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-12 gap-3 bg-[#0F1420] p-3.5 rounded-xl border border-slate-800">
        <div className="sm:col-span-5 relative">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by actor, action, details, device ID, or record ID..."
            className="w-full bg-[#0B0F17] border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="sm:col-span-4 flex items-center space-x-2">
          <Filter className="w-3.5 h-3.5 text-slate-500 shrink-0" />
          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="w-full bg-[#0B0F17] border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Audit Actions</option>
            <option value="ACCOUNT_ACTIONS">Account Protection & Remote Fixes</option>
            <option value="ATTACK">Threat Detections & Alerts</option>
            <option value="LOGIN">Authentication Events</option>
            <option value="DLT">DLT Ledger Anchors</option>
            <option value="COMMAND_ISSUED">Command Issuances</option>
            <option value="COMMAND_RESULT">Remediation Executions</option>
            <option value="DEVICE_ENROLLED">Device Enrollments</option>
          </select>
        </div>

        <div className="sm:col-span-3">
          <select
            value={deviceFilter}
            onChange={(e) => setDeviceFilter(e.target.value)}
            className="w-full bg-[#0B0F17] border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Devices ({uniqueDevices.length})</option>
            {uniqueDevices.map((d) => (
              <option key={d} value={d}>
                {d}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="bg-[#0F1420] border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/60 font-mono text-[11px] text-slate-400 uppercase tracking-wider">
                <th className="py-3 px-4">Record & Block Hash</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Actor</th>
                <th className="py-3 px-4">Target Device</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Audit Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredRecords.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500 font-mono">
                    No audit records matching filter criteria.
                  </td>
                </tr>
              ) : (
                filteredRecords.map((r, idx) => (
                  <tr
                    key={r.id}
                    className="hover:bg-slate-900/40 transition-colors group font-mono text-[11px]"
                  >
                    {/* Record & Hash */}
                    <td className="py-3 px-4">
                      <div className="space-y-0.5">
                        <div className="flex items-center space-x-1.5">
                          <LinkIcon className="w-3 h-3 text-cyan-400" />
                          <span className="font-bold text-slate-200">{r.id}</span>
                        </div>
                        <div className="flex items-center space-x-1 text-[10px] text-slate-500">
                          <span>SHA256: {r.hash.slice(0, 10)}...</span>
                          <button
                            type="button"
                            onClick={() => copyHash(r.hash)}
                            className="hover:text-cyan-400 p-0.5"
                            title="Copy full cryptographic hash"
                          >
                            {copiedHash === r.hash ? (
                              <Check className="w-3 h-3 text-emerald-400" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                          </button>
                        </div>
                      </div>
                    </td>

                    {/* Timestamp */}
                    <td className="py-3 px-4 text-slate-400">
                      <div>{new Date(r.ts).toLocaleDateString()}</div>
                      <div className="text-[10px] text-slate-500">{new Date(r.ts).toLocaleTimeString()}</div>
                    </td>

                    {/* Actor */}
                    <td className="py-3 px-4">
                      <span className="text-slate-300 font-semibold truncate block max-w-[140px]" title={r.actor}>
                        {r.actor}
                      </span>
                    </td>

                    {/* Target Device */}
                    <td className="py-3 px-4">
                      {r.device_id ? (
                        <Link
                          to={`/endpoints/${r.device_id}`}
                          className="inline-flex items-center space-x-1 text-cyan-400 hover:text-cyan-300 font-bold"
                        >
                          <Laptop className="w-3 h-3" />
                          <span>{r.device_id}</span>
                        </Link>
                      ) : (
                        <span className="text-slate-600 font-mono">—</span>
                      )}
                    </td>

                    {/* Action */}
                    <td className="py-3 px-4">{getActionBadge(r.action)}</td>

                    {/* Details */}
                    <td className="py-3 px-4 text-slate-300 max-w-md font-sans text-xs">
                      <p className="line-clamp-2" title={r.details}>
                        {r.details}
                      </p>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
