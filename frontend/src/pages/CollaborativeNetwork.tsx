import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import {
  Network,
  Building2,
  AlertTriangle,
  ArrowRight,
  ShieldAlert,
  Share2,
  CheckCircle2,
  Sparkles,
  Radio,
  Clock,
  ExternalLink,
  ShieldCheck,
  Zap,
  Activity,
  Layers
} from 'lucide-react';
import { useApp } from '../context/AppContext';

export const CollaborativeNetwork: React.FC = () => {
  const { organizations, switchOrg, activeOrg, threatPatterns, broadcastPatternToMesh, latestBroadcast } = useApp();
  const location = useLocation();
  const navigate = useNavigate();

  const [selectedPatternCode, setSelectedPatternCode] = useState<string>('TH-7821');
  const [activeBroadcast, setActiveBroadcast] = useState<any>(null);
  const [isBroadcasting, setIsBroadcasting] = useState<boolean>(false);

  // Initialize broadcast data from location state or latestBroadcast
  useEffect(() => {
    if (location.state?.broadcastData) {
      setActiveBroadcast(location.state.broadcastData);
      if (location.state.broadcastData.pattern?.patternCode) {
        setSelectedPatternCode(location.state.broadcastData.pattern.patternCode);
      }
    } else if (latestBroadcast) {
      setActiveBroadcast(latestBroadcast);
      if (latestBroadcast.pattern?.patternCode) {
        setSelectedPatternCode(latestBroadcast.pattern.patternCode);
      }
    }
  }, [location.state, latestBroadcast]);

  const handleTriggerBroadcast = async (patternCodeToUse?: string) => {
    const code = patternCodeToUse || selectedPatternCode;
    setIsBroadcasting(true);
    try {
      const res = await broadcastPatternToMesh(code);
      setActiveBroadcast(res);
    } catch (err) {
      console.error('Broadcast failed:', err);
    } finally {
      setIsBroadcasting(false);
    }
  };

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 sm:space-y-8 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-100 uppercase">COLLABORATIVE DEFENSE NETWORK</h1>
          <p className="text-xs text-slate-400 mt-1">
            Democratized cross-organization threat propagation mesh enabling real-time behavioral correlation and early warnings.
          </p>
        </div>

        {/* Live Broadcast Action Bar */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center space-x-2 bg-slate-900 border border-slate-800 rounded-xl px-3 py-1.5 font-mono text-xs">
            <span className="text-slate-400">Pattern:</span>
            <select
              value={selectedPatternCode}
              onChange={(e) => setSelectedPatternCode(e.target.value)}
              className="bg-transparent text-cyan-400 font-bold focus:outline-none"
            >
              {threatPatterns.map((tp) => (
                <option key={tp.id} value={tp.patternCode} className="bg-slate-900 text-slate-200">
                  {tp.patternCode} ({tp.originOrgName})
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={() => handleTriggerBroadcast()}
            disabled={isBroadcasting}
            className={`flex items-center space-x-2 px-4 py-2 rounded-xl border text-xs font-mono font-bold shadow-lg transition-all ${
              isBroadcasting
                ? 'bg-cyan-950/80 border-cyan-500 text-cyan-300 animate-pulse'
                : 'bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 glow-cyan'
            }`}
          >
            <Radio className={`w-4 h-4 ${isBroadcasting ? 'animate-spin' : ''}`} />
            <span>{isBroadcasting ? 'BROADCASTING...' : 'BROADCAST PATTERN TO MESH'}</span>
          </button>
        </div>
      </div>

      {/* Network Nodes Grid */}
      <div className="glass-panel p-8 rounded-2xl border border-slate-800 space-y-8">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
            <Network className="w-4 h-4 text-cyan-400" />
            <span>PARTICIPATING ORGANIZATIONAL MESH NODES</span>
          </h3>
          <div className="flex items-center space-x-3 text-xs font-mono">
            <span className="flex items-center space-x-1 text-emerald-400">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
              <span>5 Active P2P Mesh Nodes</span>
            </span>
            <span className="text-slate-500">|</span>
            <span className="text-slate-400">Click node to switch context</span>
          </div>
        </div>

        {/* Multi-Org Network Node Diagram with Broadcast Propagation Overlays */}
        <div className="grid grid-cols-1 sm:grid-cols-3 lg:grid-cols-5 gap-4 relative">
          {organizations.map((org) => {
            const isActive = activeOrg?.id === org.id;
            const peerTelemetry = activeBroadcast?.meshPropagation?.find((p: any) => p.peerOrgId === org.id);
            const isOrigin = activeBroadcast && (activeBroadcast.sourceOrg?.id === org.id || (!activeBroadcast.sourceOrg && org.id === 'org-1'));
            const earlyWarning = peerTelemetry?.earlyWarningTriggered;

            return (
              <div
                key={org.id}
                onClick={() => switchOrg(org.id)}
                className={`p-5 rounded-2xl border cursor-pointer transition-all text-center flex flex-col justify-between space-y-4 relative ${
                  isOrigin
                    ? 'bg-gradient-to-br from-cyan-950/90 to-slate-900 border-cyan-400 shadow-xl shadow-cyan-950/60 ring-2 ring-cyan-500/50 scale-105'
                    : earlyWarning
                    ? 'bg-gradient-to-br from-rose-950/60 to-slate-900 border-rose-500/80 shadow-lg shadow-rose-950/50'
                    : isActive
                    ? 'bg-slate-900/90 border-cyan-400/80 shadow-md'
                    : 'bg-slate-900/80 border-slate-800 hover:border-slate-700 hover:scale-102'
                }`}
              >
                {/* Propagation Status Pill */}
                {isOrigin && (
                  <div className="absolute -top-2.5 left-1/2 transform -translate-x-1/2 px-2 py-0.5 rounded-full bg-cyan-500 text-slate-950 font-mono text-[9px] font-black uppercase tracking-wider shadow">
                    Broadcast Origin
                  </div>
                )}
                {earlyWarning && !isOrigin && (
                  <div className="absolute -top-2.5 left-1/2 transform -translate-x-1/2 px-2 py-0.5 rounded-full bg-rose-600 text-white font-mono text-[9px] font-black uppercase tracking-wider shadow animate-pulse">
                    Early Warning
                  </div>
                )}

                <div className="p-3 rounded-full bg-slate-950 border border-slate-800 w-12 h-12 mx-auto flex items-center justify-center relative">
                  <Building2 className={`w-6 h-6 ${isOrigin ? 'text-cyan-400' : earlyWarning ? 'text-rose-400' : isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                  {earlyWarning && (
                    <span className="absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-rose-500 border-2 border-slate-950"></span>
                  )}
                </div>

                <div>
                  <div className="text-xs font-bold text-slate-100">{org.name}</div>
                  <div className="text-[10px] font-mono text-slate-400 truncate mt-0.5">{org.type}</div>
                  {peerTelemetry && !isOrigin && (
                    <div className="mt-1 text-[11px] font-mono font-bold text-rose-400">
                      {peerTelemetry.similarityPercentage}% Sequence Match
                    </div>
                  )}
                </div>

                <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-[10px] font-mono">
                  <span className="text-slate-400">Risk Score:</span>
                  <span
                    className={`font-bold px-1.5 py-0.5 rounded border ${
                      org.riskScore >= 80
                        ? 'bg-rose-950 text-rose-400 border-rose-800'
                        : org.riskScore >= 65
                        ? 'bg-amber-950 text-amber-400 border-amber-800'
                        : 'bg-emerald-950 text-emerald-400 border-emerald-800'
                    }`}
                  >
                    {org.riskScore} RS
                  </span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Live Broadcast Propagation Telemetry Card */}
        {activeBroadcast && (
          <div className="p-6 rounded-2xl bg-gradient-to-r from-cyan-950/60 via-slate-900 to-rose-950/40 border border-cyan-500/70 space-y-5 animate-fadeIn">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
              <div className="flex items-center space-x-3">
                <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                  <Radio className="w-5 h-5 animate-pulse" />
                </div>
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="font-bold text-slate-100 text-sm">ACTIVE THREAT MESH BROADCAST:</span>
                    <span className="font-mono text-cyan-400 font-bold">{activeBroadcast.pattern?.patternCode || selectedPatternCode}</span>
                    <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-mono text-[10px]">
                      DLT Block #{activeBroadcast.ledgerBlock?.blockNumber || 10421}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Originating Node: <strong>{activeBroadcast.sourceOrg?.name || 'Demo Bank'}</strong> • Disseminated across {activeBroadcast.meshPropagation?.length || 4} peer mesh nodes.
                  </p>
                </div>
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={() => navigate('/dlt-ledger')}
                  className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs font-mono text-slate-300 flex items-center space-x-1"
                >
                  <span>Inspect Ledger Block</span>
                  <ExternalLink className="w-3 h-3" />
                </button>
              </div>
            </div>

            {/* Early Warning Banner */}
            {(() => {
              const warningPeers = activeBroadcast.meshPropagation?.filter((p: any) => p.earlyWarningTriggered) || [];
              if (warningPeers.length === 0) return null;
              return (
                <div className="p-4 rounded-xl bg-rose-950/90 border-2 border-rose-500 text-rose-200 text-xs font-mono space-y-1 shadow-lg shadow-rose-950/50 animate-fadeIn">
                  <div className="flex items-center space-x-2 text-rose-400 font-bold text-sm uppercase">
                    <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 animate-bounce" />
                    <span>🚨 CROSS-ORGANIZATION EARLY WARNING TRIGGERED</span>
                  </div>
                  <p className="text-slate-300 font-sans text-xs">
                    {warningPeers.map((p: any) => `${p.peerOrgName} (${p.similarityPercentage}% Sequence Overlap)`).join(', ')} exhibiting active attack progression matching Threat Pattern <strong>{activeBroadcast.pattern?.patternCode || selectedPatternCode}</strong>.
                  </p>
                </div>
              );
            })()}

            {/* Peer Reception Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
              {activeBroadcast.meshPropagation?.map((peer: any) => {
                const isSelectedForInspection = (activeBroadcast.selectedPeerId || 'org-2') === peer.peerOrgId;
                return (
                  <div
                    key={peer.peerOrgId}
                    onClick={() => setActiveBroadcast({ ...activeBroadcast, selectedPeerId: peer.peerOrgId })}
                    className={`p-4 rounded-xl border flex flex-col justify-between space-y-3 cursor-pointer transition-all ${
                      isSelectedForInspection
                        ? 'border-cyan-400 bg-slate-900/90 shadow-lg ring-1 ring-cyan-500/50 scale-[1.01]'
                        : peer.earlyWarningTriggered
                        ? 'bg-rose-950/25 border-rose-700/80 hover:border-rose-500'
                        : 'bg-slate-950/70 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="font-bold text-slate-100 flex items-center space-x-2">
                          <span>{peer.peerOrgName}</span>
                          {isSelectedForInspection && (
                            <span className="text-[10px] text-cyan-400 font-normal">● Inspecting Alignment</span>
                          )}
                        </div>
                        <div className="text-[10px] text-slate-500">{peer.peerType} • {peer.latencyMs}ms latency</div>
                      </div>
                      <span
                        className={`px-2 py-0.5 rounded border text-[10px] font-bold ${
                          peer.earlyWarningTriggered
                            ? 'bg-rose-950 text-rose-300 border-rose-700 animate-pulse'
                            : 'bg-emerald-950 text-emerald-400 border-emerald-800'
                        }`}
                      >
                        {peer.earlyWarningTriggered ? '🚨 EARLY WARNING' : '✓ NORMAL TELEMETRY'}
                      </span>
                    </div>

                    <div className="space-y-1 text-[11px]">
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400">Order-Aware Sequence Match:</span>
                        <span className={`font-black ${peer.similarityPercentage >= 65 ? 'text-rose-400' : 'text-slate-300'}`}>
                          {peer.similarityPercentage}% Match
                        </span>
                      </div>
                      <div className="text-slate-300 truncate">
                        Matching Signature: <span className="text-slate-400">{peer.matchingEvents?.join(' → ') || 'No attack signatures'}</span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Aligned Side-by-Side Sequence Comparison for Inspected Peer */}
            {(() => {
              const currentPeerId = activeBroadcast.selectedPeerId || 'org-2';
              const targetPeer = activeBroadcast.meshPropagation?.find((p: any) => p.peerOrgId === currentPeerId) || activeBroadcast.meshPropagation?.[0];
              if (!targetPeer) return null;

              const patternSeq = activeBroadcast.pattern?.patternSequence || ['FAILED_LOGIN', 'SUCCESSFUL_LOGIN', 'NEW_DEVICE', 'UNUSUAL_LOCATION', 'PRIVILEGE_ESCALATION', 'LARGE_DATA_TRANSFER'];
              const breakdown = targetPeer.alignedBreakdown || [];

              return (
                <div className="mt-6 p-6 rounded-2xl bg-slate-950 border border-cyan-500/40 space-y-5 animate-fadeIn">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
                    <div>
                      <h4 className="text-sm font-bold text-slate-100 uppercase tracking-wider flex items-center space-x-2">
                        <Activity className="w-4 h-4 text-cyan-400" />
                        <span>ALIGNED SEQUENCE BREAKDOWN: {activeBroadcast.pattern?.patternCode || selectedPatternCode} vs {targetPeer.peerOrgName.toUpperCase()}</span>
                      </h4>
                      <p className="text-xs text-slate-400 mt-0.5">
                        Weighted Longest Common Subsequence (LCS) ordered alignment identifying matched vs missing adversary TTPs.
                      </p>
                    </div>

                    <div className="flex items-center space-x-3 text-xs font-mono">
                      <div className="px-3 py-1 rounded-lg bg-slate-900 border border-slate-800">
                        <span className="text-slate-400">Similarity: </span>
                        <span className={`font-bold ${targetPeer.similarityPercentage >= 65 ? 'text-rose-400' : 'text-emerald-400'}`}>
                          {targetPeer.similarityPercentage}%
                        </span>
                      </div>
                      <span className={`px-2.5 py-1 rounded border text-[10px] font-bold ${
                        targetPeer.earlyWarningTriggered
                          ? 'bg-rose-950 text-rose-300 border-rose-800'
                          : 'bg-emerald-950 text-emerald-400 border-emerald-800'
                      }`}>
                        {targetPeer.earlyWarningTriggered ? 'EARLY WARNING' : 'NORMAL'}
                      </span>
                    </div>
                  </div>

                  {/* Aligned Sequence Comparison Table */}
                  <div className="space-y-2 font-mono text-xs">
                    <div className="grid grid-cols-12 gap-2 text-[10px] text-slate-500 uppercase pb-1 border-b border-slate-800/80 px-2">
                      <span className="col-span-1">#</span>
                      <span className="col-span-5">Source Threat Pattern ({activeBroadcast.pattern?.patternCode || selectedPatternCode})</span>
                      <span className="col-span-2 text-center">Alignment</span>
                      <span className="col-span-4">Target Telemetry ({targetPeer.peerOrgName})</span>
                    </div>

                    {breakdown.length > 0 ? (
                      breakdown.map((item: any, i: number) => {
                        const isMatched = item.status === 'MATCHED';
                        const isMissing = item.status === 'MISSING_IN_TARGET';

                        return (
                          <div
                            key={i}
                            className={`grid grid-cols-12 gap-2 items-center p-2.5 rounded-lg border text-xs ${
                              isMatched
                                ? 'bg-emerald-950/30 border-emerald-800/80 text-emerald-200'
                                : isMissing
                                ? 'bg-amber-950/20 border-amber-800/60 text-amber-300'
                                : 'bg-slate-900/60 border-slate-800 text-slate-300'
                            }`}
                          >
                            <span className="col-span-1 text-slate-500 text-[10px]">Step {i + 1}</span>

                            <div className="col-span-5 font-semibold flex items-center space-x-1.5 truncate">
                              {item.eventA ? (
                                <>
                                  <span className={`w-2 h-2 rounded-full shrink-0 ${isMatched ? 'bg-emerald-400' : 'bg-amber-400'}`}></span>
                                  <span className="truncate">{item.eventA}</span>
                                </>
                              ) : (
                                <span className="text-slate-600 italic">— [No Pattern Precedent] —</span>
                              )}
                            </div>

                            <div className="col-span-2 text-center">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                                isMatched
                                  ? 'bg-emerald-950 text-emerald-300 border-emerald-700'
                                  : isMissing
                                  ? 'bg-amber-950 text-amber-300 border-amber-700'
                                  : 'bg-slate-800 text-slate-400 border-slate-700'
                              }`}>
                                {isMatched ? '✓ MATCHED' : isMissing ? '⚠️ MISSING' : '+ EXTRA'}
                              </span>
                            </div>

                            <div className="col-span-4 font-semibold flex items-center space-x-1.5 truncate">
                              {item.eventB ? (
                                <>
                                  <span className={`w-2 h-2 rounded-full shrink-0 ${isMatched ? 'bg-emerald-400' : 'bg-slate-500'}`}></span>
                                  <span className="truncate">{item.eventB}</span>
                                </>
                              ) : (
                                <span className="text-amber-400/70 italic text-[11px]">— [Not Detected Yet] —</span>
                              )}
                            </div>
                          </div>
                        );
                      })
                    ) : (
                      // Fallback side-by-side display if breakdown is not present
                      patternSeq.map((event: string, i: number) => {
                        const isMatched = targetPeer.matchingEvents?.includes(event);
                        return (
                          <div
                            key={i}
                            className={`grid grid-cols-12 gap-2 items-center p-2.5 rounded-lg border text-xs ${
                              isMatched
                                ? 'bg-emerald-950/30 border-emerald-800/80 text-emerald-200'
                                : 'bg-amber-950/20 border-amber-800/60 text-amber-300'
                            }`}
                          >
                            <span className="col-span-1 text-slate-500 text-[10px]">Step {i + 1}</span>
                            <span className="col-span-5 font-semibold truncate">{event}</span>
                            <div className="col-span-2 text-center">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                                isMatched ? 'bg-emerald-950 text-emerald-300 border-emerald-700' : 'bg-amber-950 text-amber-300 border-amber-700'
                              }`}>
                                {isMatched ? '✓ MATCHED' : '⚠️ MISSING'}
                              </span>
                            </div>
                            <span className="col-span-4 font-semibold truncate">
                              {isMatched ? event : <span className="text-amber-400/70 italic text-[11px]">— Not Detected in Telemetry —</span>}
                            </span>
                          </div>
                        );
                      })
                    )}
                  </div>
                </div>
              );
            })()}
          </div>
        )}
      </div>
    </div>
  );
};
