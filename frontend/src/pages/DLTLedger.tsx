import React, { useState } from 'react';
import {
  Database,
  ShieldCheck,
  ShieldAlert,
  CheckCircle2,
  Lock,
  ArrowRight,
  RefreshCw,
  Info,
  Link,
  FileCheck,
  Search,
  Plus,
  AlertTriangle,
  RotateCcw,
  Check,
  UserCheck
} from 'lucide-react';
import { useApp } from '../context/AppContext';

export const DLTLedger: React.FC = () => {
  const {
    ledgerRecords,
    verifyLedgerRecord,
    tamperLedgerDemo,
    resetLedgerDemo,
    validateLedgerBlock,
    addCustomLedgerBlock,
    activeOrg
  } = useApp();

  const [selectedBlockNumber, setSelectedBlockNumber] = useState<number>(10421);
  const [verificationResult, setVerificationResult] = useState<any>(null);
  const [chainResult, setChainResult] = useState<any>(null);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [isTampering, setIsTampering] = useState<boolean>(false);
  const [isResetting, setIsResetting] = useState<boolean>(false);
  const [isValidating, setIsValidating] = useState<boolean>(false);

  // New Block Form (deterministic counter default)
  const [newThreatId, setNewThreatId] = useState('TH-9100');
  const [newHash, setNewHash] = useState('c4f2e89d1b7a305e9284716352410982c4f2e89d1b7a305e9284716352410982');

  const handleVerifyIntegrity = async (blockNum?: number) => {
    setIsVerifying(true);
    const target = blockNum ?? selectedBlockNumber;
    const res = await verifyLedgerRecord(target);
    setVerificationResult(res.verification);
    setChainResult(res.chainVerification || {
      isVerified: res.isChainValid,
      brokenBlockNumber: res.brokenBlockNumber,
      details: res.details
    });
    setIsVerifying(false);
  };

  const handleTamperDemo = async () => {
    setIsTampering(true);
    await tamperLedgerDemo(10420);
    // Auto-verify to immediately show the broken chain
    await handleVerifyIntegrity(10420);
    setIsTampering(false);
  };

  const handleResetLedger = async () => {
    setIsResetting(true);
    await resetLedgerDemo();
    setVerificationResult(null);
    setChainResult(null);
    setSelectedBlockNumber(10421);
    setIsResetting(false);
  };

  const handleAddValidator = async (blockNumber: number) => {
    setIsValidating(true);
    const validatorName = activeOrg?.name || 'State University';
    await validateLedgerBlock(blockNumber, validatorName);
    // Re-verify after adding signature
    await handleVerifyIntegrity(blockNumber);
    setIsValidating(false);
  };

  const handleMineBlock = async () => {
    if (!newThreatId.trim()) return;
    await addCustomLedgerBlock(newThreatId.trim(), activeOrg?.name || 'Demo Bank', newHash.trim());
    const nextSeq = ledgerRecords.length + 9200;
    setNewThreatId(`TH-${nextSeq}`);
  };

  const selectedBlock = ledgerRecords.find((b) => b.blockNumber === selectedBlockNumber) || ledgerRecords[ledgerRecords.length - 1];
  const isChainBroken = chainResult && !chainResult.isVerified;
  const brokenNum = chainResult?.brokenBlockNumber;

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 sm:space-y-8 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex flex-wrap items-center gap-2 sm:gap-3">
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-100 uppercase">
              DLT TRUST LEDGER
            </h1>
            <span className="px-2.5 py-1 rounded-full text-xs font-mono bg-cyan-950 text-cyan-400 border border-cyan-800">
              SHA-256 HASH-CHAIN CONSENSUS
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Immutable, zero-knowledge threat pattern registry backed by sequential SHA-256 hashing and multi-party validator quorum.
          </p>
        </div>

        {/* Action Buttons: Verify, Tamper Demo, Reset */}
        <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
          <button
            onClick={() => handleVerifyIntegrity()}
            disabled={isVerifying}
            className="flex-1 sm:flex-initial flex items-center justify-center space-x-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 font-bold text-xs shadow-lg glow-cyan transition-all disabled:opacity-50"
          >
            <ShieldCheck className={`w-4 h-4 shrink-0 ${isVerifying ? 'animate-spin' : ''}`} />
            <span>{isVerifying ? 'VERIFYING...' : 'VERIFY INTEGRITY'}</span>
          </button>

          <button
            onClick={handleTamperDemo}
            disabled={isTampering}
            className="flex-1 sm:flex-initial flex items-center justify-center space-x-2 px-4 py-2.5 rounded-xl bg-rose-950/80 hover:bg-rose-900 border border-rose-600/80 text-rose-300 font-bold text-xs shadow-lg transition-all disabled:opacity-50"
            title="Demonstrate malicious alteration of Block #10420"
          >
            <ShieldAlert className={`w-4 h-4 text-rose-400 shrink-0 ${isTampering ? 'animate-spin' : ''}`} />
            <span>{isTampering ? 'TAMPERING...' : 'TAMPER DEMO'}</span>
          </button>

          <button
            onClick={handleResetLedger}
            disabled={isResetting}
            className="flex-1 sm:flex-initial flex items-center justify-center space-x-1.5 px-3.5 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 font-mono text-xs transition-all disabled:opacity-50"
            title="Restore pristine baseline chain"
          >
            <RotateCcw className={`w-3.5 h-3.5 shrink-0 ${isResetting ? 'animate-spin' : ''}`} />
            <span>Restore</span>
          </button>
        </div>
      </div>

      {/* Off-Chain Privacy Notice */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-cyan-800/60 text-xs font-mono text-cyan-300 flex items-start sm:items-center space-x-3">
        <Info className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5 sm:mt-0" />
        <div className="space-y-0.5">
          <span className="font-bold uppercase tracking-wider text-cyan-200">
            OFF-CHAIN PRIVACY ARCHITECTURE:
          </span>
          <p className="text-slate-300 font-sans text-xs">
            Sensitive organizational logs, employee PII, internal IPs, and credentials remain <strong>100% off-chain</strong>. The DLT ledger records only anonymized threat metadata, SHA-256 pattern signatures, and validator consensus proofs.
          </p>
        </div>
      </div>

      {/* Tamper Alert Banner (if chain broken) */}
      {isChainBroken && (
        <div className="p-4 rounded-2xl bg-rose-950/90 border-2 border-rose-500 text-rose-200 text-xs font-mono space-y-2 animate-fadeIn shadow-2xl shadow-rose-950/80">
          <div className="flex items-center space-x-2 text-rose-400 font-bold text-sm uppercase">
            <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 animate-bounce" />
            <span>CRYPTOGRAPHIC TAMPER DETECTED AT BLOCK #{brokenNum}</span>
          </div>
          <p className="text-slate-300 font-sans text-xs">
            {chainResult.details}
          </p>
          <div className="flex items-center space-x-3 pt-1">
            <button
              onClick={handleResetLedger}
              className="px-3 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs font-sans"
            >
              Repair & Restore Ledger
            </button>
            <span className="text-rose-400 text-[11px]">Notice: Block #{brokenNum} and downstream blocks turn RED below.</span>
          </div>
        </div>
      )}

      {/* Visual Blockchain Sequence with Dynamic Red Highlighting */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
            <Link className="w-4 h-4 text-cyan-400" />
            <span>CRYPTOGRAPHIC LEDGER BLOCKCHAIN SEQUENCE</span>
          </h3>
          <div className="flex items-center space-x-3 text-xs font-mono">
            <span className={isChainBroken ? 'text-rose-400 font-bold' : 'text-emerald-400'}>
              {isChainBroken ? '● Tamper Detected' : '● Chain Verified'}
            </span>
            <span className="text-slate-500">|</span>
            <span className="text-slate-400">{ledgerRecords.length} Blocks</span>
          </div>
        </div>

        {/* Visual Blocks Sequence */}
        <div className="flex flex-col md:flex-row items-stretch md:items-center gap-4 overflow-x-auto py-4">
          {ledgerRecords.map((block, idx) => {
            const isSelected = selectedBlockNumber === block.blockNumber;
            const isDirectBroken = isChainBroken && brokenNum === block.blockNumber;
            const isDownstreamBroken = isChainBroken && brokenNum !== null && block.blockNumber > brokenNum;

            let cardStyle = 'bg-slate-900/80 border-slate-800 hover:border-slate-700';
            let badgeStyle = 'bg-emerald-950 text-emerald-400 border-emerald-800';

            if (isDirectBroken) {
              cardStyle = 'bg-rose-950/80 border-2 border-rose-500 shadow-xl shadow-rose-950 ring-2 ring-rose-500/50 scale-105';
              badgeStyle = 'bg-rose-900 text-rose-200 border-rose-600 animate-pulse';
            } else if (isDownstreamBroken) {
              cardStyle = 'bg-amber-950/40 border border-amber-600/70 shadow-lg';
              badgeStyle = 'bg-amber-950 text-amber-300 border-amber-800';
            } else if (isSelected) {
              cardStyle = 'bg-gradient-to-br from-cyan-950/80 to-slate-900 border-cyan-400 shadow-lg shadow-cyan-950/50 scale-105';
            }

            return (
              <React.Fragment key={block.blockNumber}>
                <div
                  onClick={() => {
                    setSelectedBlockNumber(block.blockNumber);
                    setVerificationResult(null);
                  }}
                  className={`p-4 rounded-xl border cursor-pointer w-full md:w-64 transition-all relative ${cardStyle}`}
                >
                  {/* Status Indicator Pill */}
                  {isDirectBroken && (
                    <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-2.5 py-0.5 rounded-full bg-rose-600 text-white font-mono text-[9px] font-black uppercase tracking-wider shadow">
                      BROKEN HASH
                    </div>
                  )}
                  {isDownstreamBroken && (
                    <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-2.5 py-0.5 rounded-full bg-amber-600 text-white font-mono text-[9px] font-black uppercase tracking-wider shadow">
                      SEVERED LINK
                    </div>
                  )}

                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-bold text-cyan-400">Block #{block.blockNumber}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${badgeStyle}`}>
                      {isDirectBroken ? 'TAMPERED' : block.status}
                    </span>
                  </div>

                  <div className="mt-2 text-xs font-bold text-slate-100 truncate">
                    Threat: <span className={isDirectBroken ? 'text-rose-400 font-mono' : 'text-slate-200'}>{block.threatId}</span>
                  </div>
                  <div className="text-[10px] font-mono text-slate-400 mt-0.5">Reporter: {block.reporterOrg}</div>

                  <div className="mt-2.5 space-y-1 text-[10px] font-mono">
                    <div className="text-slate-400 truncate">
                      Prev: <span className="text-slate-500">{block.previousHash.slice(0, 10)}...</span>
                    </div>
                    <div className="text-slate-400 truncate">
                      Hash: <span className={isDirectBroken ? 'text-rose-400 font-bold' : 'text-cyan-400'}>{block.blockHash.slice(0, 10)}...</span>
                    </div>
                  </div>

                  {/* Validator count badge */}
                  <div className="mt-3 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-400">
                    <span>Quorum: {block.validators.length} Signatures</span>
                    {block.status !== 'CONFIRMED' && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleAddValidator(block.blockNumber);
                        }}
                        disabled={isValidating}
                        className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 hover:bg-cyan-900"
                      >
                        + Sign
                      </button>
                    )}
                  </div>
                </div>

                {idx < ledgerRecords.length - 1 && (
                  <div className={`hidden md:block shrink-0 ${isChainBroken && block.blockNumber >= (brokenNum ?? 0) ? 'text-rose-500' : 'text-cyan-500'}`}>
                    <ArrowRight className="w-5 h-5 animate-pulse" />
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* Selected Block Inspector & Verification Panel */}
      {selectedBlock && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Detailed Block Inspector Card */}
          <div className="lg:col-span-2 glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
                <Database className="w-4 h-4 text-cyan-400" />
                <span>BLOCK #{selectedBlock.blockNumber} METADATA & HASH SIGNATURE</span>
              </h3>
              <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold border ${
                selectedBlock.status === 'CONFIRMED'
                  ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                  : 'bg-amber-950 text-amber-400 border-amber-800'
              }`}>
                {selectedBlock.status}
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
              <div className="p-3 rounded-xl bg-slate-900/90 border border-slate-800">
                <span className="text-slate-500 uppercase text-[10px]">Threat Pattern Code</span>
                <div className="text-sm font-bold text-slate-200 mt-0.5">{selectedBlock.threatId}</div>
              </div>

              <div className="p-3 rounded-xl bg-slate-900/90 border border-slate-800">
                <span className="text-slate-500 uppercase text-[10px]">Reporter Organization</span>
                <div className="text-sm font-bold text-slate-200 mt-0.5">{selectedBlock.reporterOrg}</div>
              </div>

              <div className="md:col-span-2 p-3 rounded-xl bg-slate-900/90 border border-slate-800">
                <span className="text-slate-500 uppercase text-[10px]">Previous Block Hash (Linkage Pointer)</span>
                <div className="text-xs text-slate-300 break-all mt-0.5">{selectedBlock.previousHash}</div>
              </div>

              <div className="md:col-span-2 p-3 rounded-xl bg-slate-950 border border-cyan-800/60">
                <span className="text-cyan-400 uppercase text-[10px] font-bold">SHA-256 Block Hash (Payload Signature)</span>
                <div className="text-xs text-cyan-300 break-all font-bold mt-0.5">{selectedBlock.blockHash}</div>
              </div>

              <div className="md:col-span-2 p-3 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
                <span className="text-slate-500 uppercase text-[10px]">Validator Quorum Signatures</span>
                <div className="flex flex-wrap items-center gap-2">
                  {selectedBlock.validators.map((val: string, i: number) => (
                    <span key={i} className="px-2.5 py-1 rounded-lg bg-slate-800 border border-slate-700 text-slate-200 flex items-center space-x-1">
                      <UserCheck className="w-3 h-3 text-cyan-400" />
                      <span>{val}</span>
                    </span>
                  ))}
                  {selectedBlock.status !== 'CONFIRMED' && (
                    <button
                      onClick={() => handleAddValidator(selectedBlock.blockNumber)}
                      disabled={isValidating}
                      className="px-2.5 py-1 rounded-lg bg-cyan-500 text-slate-950 font-bold hover:bg-cyan-400"
                    >
                      + Add Consensus Signature
                    </button>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Verification Status Card */}
          <div className="glass-panel p-6 rounded-2xl border border-slate-800 flex flex-col justify-between space-y-4">
            <div className="space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <h4 className="text-xs font-mono uppercase font-bold text-slate-300">INTEGRITY AUDIT</h4>
                <button
                  onClick={() => handleVerifyIntegrity(selectedBlock.blockNumber)}
                  disabled={isVerifying}
                  className="px-3 py-1 rounded-lg bg-cyan-950 border border-cyan-800 text-cyan-300 text-xs font-mono hover:bg-cyan-900"
                >
                  Verify Block #{selectedBlock.blockNumber}
                </button>
              </div>

              {verificationResult ? (
                <div className={`p-4 rounded-xl border space-y-3 ${
                  verificationResult.isVerified
                    ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                    : 'bg-rose-950/40 border-rose-800 text-rose-300'
                }`}>
                  <div className="flex items-center space-x-2 font-bold text-xs font-mono">
                    {verificationResult.isVerified ? (
                      <>
                        <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                        <span>BLOCK HASH INTACT</span>
                      </>
                    ) : (
                      <>
                        <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                        <span>HASH MISMATCH / TAMPER DETECTED</span>
                      </>
                    )}
                  </div>
                  <p className="text-[11px] leading-relaxed font-sans text-slate-300">
                    {verificationResult.details}
                  </p>
                </div>
              ) : (
                <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 text-slate-400 text-xs font-mono text-center">
                  Click "VERIFY INTEGRITY" above to execute cryptographic audit across all blocks.
                </div>
              )}
            </div>

            {/* Validator Workflow Stages */}
            <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2 text-xs font-mono">
              <span className="text-slate-500 uppercase text-[10px]">Consensus Workflow Stages</span>
              <div className="flex items-center justify-between text-[11px]">
                <span className={selectedBlock.validators.length >= 1 ? 'text-cyan-400 font-bold' : 'text-slate-500'}>
                  1. Reported
                </span>
                <span className="text-slate-600">→</span>
                <span className={selectedBlock.validators.length >= 2 ? 'text-cyan-400 font-bold' : 'text-slate-500'}>
                  2. Verified (1)
                </span>
                <span className="text-slate-600">→</span>
                <span className={selectedBlock.validators.length >= 3 ? 'text-cyan-400 font-bold' : 'text-slate-500'}>
                  3. Quorum (3)
                </span>
                <span className="text-slate-600">→</span>
                <span className={selectedBlock.status === 'CONFIRMED' ? 'text-emerald-400 font-bold' : 'text-slate-500'}>
                  CONFIRMED
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Mine New Block Card */}
      <div className="glass-panel p-6 rounded-2xl border border-cyan-500/30 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
            <Plus className="w-4 h-4 text-cyan-400" />
            <span>MINE NEW DLT THREAT PROOF BLOCK</span>
          </h3>
          <span className="text-xs font-mono text-slate-500">Append-only cryptographic consensus</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          <div>
            <label className="block text-slate-400 font-mono mb-1">Threat Pattern Code</label>
            <input
              type="text"
              value={newThreatId}
              onChange={(e) => setNewThreatId(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="md:col-span-2">
            <label className="block text-slate-400 font-mono mb-1">Anonymized Pattern SHA-256 Hash</label>
            <div className="flex items-center space-x-2">
              <input
                type="text"
                value={newHash}
                onChange={(e) => setNewHash(e.target.value)}
                className="flex-1 px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 font-mono text-[11px] focus:outline-none focus:border-cyan-500 truncate"
              />
              <button
                onClick={handleMineBlock}
                className="px-4 py-2 rounded-lg bg-emerald-500 text-slate-950 font-bold text-xs shrink-0 glow-cyan hover:bg-emerald-400"
              >
                Commit Block
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
