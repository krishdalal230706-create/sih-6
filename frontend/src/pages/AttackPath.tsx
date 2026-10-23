import React, { useState } from 'react';
import {
  GitCommit,
  User,
  Key,
  Server,
  Database,
  Lock,
  ArrowRight,
  ShieldAlert,
  Info,
  CheckCircle2,
  Zap,
  AlertTriangle,
  Sparkles,
  Scissors
} from 'lucide-react';
import { useApp } from '../context/AppContext';

export const AttackPath: React.FC = () => {
  const { executeResponseAction, responseActions, addNotification, activeOrg, remediateWeakPoint } = useApp();
  const [selectedNodeId, setSelectedNodeId] = useState<string>('node-2');
  const [deployedNodes, setDeployedNodes] = useState<Record<string, boolean>>({});
  const [whatIfFix, setWhatIfFix] = useState<boolean>(false);
  const [isRemediating, setIsRemediating] = useState<boolean>(false);

  const nodes = [
    {
      id: 'node-1',
      title: 'Target User',
      subtitle: 'Employee Mailbox (admin@demobank.com)',
      type: 'ENTRY',
      icon: User,
      risk: 45,
      severity: 'MEDIUM',
      color: 'border-amber-500 text-amber-400 bg-amber-950/20',
      exploitability: 'High',
      impact: 'MEDIUM',
      reason: 'Phishing email bypasses SPF/DKIM filters.',
      control: 'Advanced Email Filtering & Security Awareness'
    },
    {
      id: 'node-2',
      title: 'Identity Provider',
      subtitle: 'Okta / Azure AD SSO Console',
      type: 'WEAKNESS',
      icon: Key,
      risk: 91,
      severity: 'CRITICAL',
      color: 'border-rose-500 text-rose-400 bg-rose-950/40 glow-red',
      exploitability: 'Critical',
      impact: 'CRITICAL',
      reason: 'Password reused and SMS OTP intercepted due to lack of hardware keys.',
      control: 'Enforce FIDO2 WebAuthn Hardware Keys',
      isWeakestLink: true
    },
    {
      id: 'node-3',
      title: 'Application Server',
      subtitle: 'Core Banking API Gateway (DMZ)',
      type: 'TRANSIT',
      icon: Server,
      risk: 78,
      severity: 'HIGH',
      color: 'border-amber-500 text-amber-400 bg-amber-950/20',
      exploitability: 'High',
      impact: 'HIGH',
      reason: 'Service account tokens cached in application memory.',
      control: 'Privileged Access Management (PAM) & Token Expiration'
    },
    {
      id: 'node-4',
      title: 'Core Database',
      subtitle: 'Customer Oracle Production DB',
      type: 'TARGET',
      icon: Database,
      risk: 88,
      severity: 'CRITICAL',
      color: 'border-rose-500 text-rose-400 bg-rose-950/30',
      exploitability: 'Critical',
      impact: 'CRITICAL',
      reason: 'Internal port 1521 exposed without zero-trust microsegmentation.',
      control: 'Zero Trust Microsegmentation & Database Firewall'
    },
    {
      id: 'node-5',
      title: 'Sensitive PII Data',
      subtitle: 'Encrypted Exfiltration S3 Bucket',
      type: 'EXFILTRATION',
      icon: Lock,
      risk: 94,
      severity: 'CRITICAL',
      color: 'border-rose-500 text-rose-400 bg-rose-950/40',
      exploitability: 'Critical',
      impact: 'CRITICAL',
      reason: 'No egress filtering on outbound HTTPS cloud traffic.',
      control: 'Data Loss Prevention (DLP) & CASB Proxy'
    }
  ];

  const selectedNode = nodes.find((n) => n.id === selectedNodeId) || nodes[1];

  const handleDeployNodeControl = async (nodeId: string) => {
    setDeployedNodes((prev) => ({ ...prev, [nodeId]: true }));
    const orgActions = activeOrg ? responseActions.filter((a) => a.orgId === activeOrg.id) : [];
    const act = orgActions.find((a) => a.status !== 'Completed') || orgActions[0];
    if (act) {
      await executeResponseAction(act.id, act.incidentId, 'Completed');
    }
    addNotification('Control Deployed', `Deployed "${selectedNode.control}" on ${selectedNode.title}. Node risk mitigated!`, 'SUCCESS', '/attack-path');
  };

  const handleQuickFixWeakPoint = async () => {
    setIsRemediating(true);
    await remediateWeakPoint();
    setDeployedNodes((prev) => ({ ...prev, 'node-2': true }));
    setIsRemediating(false);
    setWhatIfFix(false);
    addNotification('Weak Point Neutralized', 'Enforced FIDO2 WebAuthn keys. Lateral attack chain severed!', 'SUCCESS', '/attack-path');
  };

  const isCurrentDeployed = deployedNodes[selectedNode.id];

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 sm:space-y-8 max-w-7xl mx-auto">
      {/* Prominent Visible Simulation Notice */}
      <div className="p-3.5 rounded-2xl bg-amber-950/40 border border-amber-800/80 text-amber-300 font-mono text-xs flex items-center justify-between gap-3 shadow-md">
        <div className="flex items-center space-x-2.5">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 animate-pulse" />
          <span>
            <strong>Simulation only. No real attack is performed.</strong> All DAG lateral movement paths and access privileges are safely modelled.
          </span>
        </div>
        <span className="hidden md:inline px-2 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-800 text-[10px] font-bold">
          DAG SANDBOX
        </span>
      </div>

      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-100 uppercase">ATTACK PATH VISUALIZATION</h1>
            <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 text-[10px] font-mono border border-cyan-800 font-bold">
              DAG TOPOLOGY
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Interactive Directed Acyclic Graph (DAG) visualizing how an adversary moves from initial entry to core sensitive data assets.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3 w-full sm:w-auto">
          {/* Counterfactual "What if I fix this?" Toggle */}
          <button
            onClick={() => setWhatIfFix(!whatIfFix)}
            className={`flex items-center space-x-2 px-3.5 py-2 rounded-xl border text-xs font-mono font-bold transition-all ${
              whatIfFix
                ? 'bg-emerald-950 text-emerald-300 border-emerald-500 ring-2 ring-emerald-500/40 shadow-lg shadow-emerald-950/50'
                : 'bg-slate-900 text-slate-300 border-slate-800 hover:border-slate-700'
            }`}
          >
            <Sparkles className={`w-3.5 h-3.5 ${whatIfFix ? 'text-emerald-400 animate-spin' : 'text-slate-400'}`} />
            <span>{whatIfFix ? 'COUNTERFACTUAL ON' : 'WHAT IF I FIX THIS?'}</span>
          </button>

          <div className="px-3.5 py-2 rounded-xl bg-slate-900 border border-slate-800 text-left sm:text-right">
            <div className="text-[10px] font-mono text-slate-400 uppercase font-bold">Composite Path Score</div>
            <div className={`text-base sm:text-lg font-bold font-mono ${
              whatIfFix || deployedNodes['node-2'] ? 'text-emerald-400' : 'text-rose-400'
            }`}>
              {whatIfFix ? '60 / 100 (PROJECTED)' : deployedNodes['node-2'] ? '58 / 100 — MITIGATED' : '89 / 100 — CRITICAL'}
            </div>
          </div>
        </div>
      </div>

      {/* What-If Counterfactual Projected Banner */}
      {whatIfFix && !deployedNodes['node-2'] && (
        <div className="p-4 rounded-xl bg-emerald-950/70 border-2 border-emerald-500 text-emerald-200 text-xs font-mono flex flex-col md:flex-row md:items-center justify-between gap-3 animate-fadeIn shadow-lg shadow-emerald-950/50">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-emerald-900/60 text-emerald-300 shrink-0">
              <Scissors className="w-5 h-5 text-emerald-400" />
            </div>
            <div>
              <div className="font-bold text-sm text-emerald-300 uppercase tracking-wide">
                PROJECTED CHOKEPOINT SEVERANCE
              </div>
              <p className="text-slate-300 text-xs mt-0.5">
                Deploying FIDO2 Hardware Keys on <strong className="text-emerald-300">Identity Provider</strong> breaks the attack path before adversaries reach the Application Server.
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-3 shrink-0">
            <div className="px-3 py-1.5 rounded-lg bg-slate-950/90 border border-emerald-800 text-right">
              <span className="text-[10px] text-slate-400">Path Score Drop: </span>
              <strong className="text-emerald-400 text-sm">89 → 60 (-29 pts)</strong>
            </div>

            <button
              onClick={handleQuickFixWeakPoint}
              disabled={isRemediating}
              className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs flex items-center space-x-1.5"
            >
              <Zap className="w-3.5 h-3.5 fill-slate-950" />
              <span>{isRemediating ? 'Neutralizing...' : 'Sever Attack Chain Now'}</span>
            </button>
          </div>
        </div>
      )}

      {/* Main Path Diagram & Detail Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Graph Layout */}
        <div className="lg:col-span-2 glass-panel p-6 rounded-2xl border border-slate-800 space-y-6">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
              <GitCommit className="w-4 h-4 text-cyan-400" />
              <span>DAG LATERAL MOVEMENT FLOW</span>
            </h3>
            <span className="text-xs font-mono text-slate-400">Click any node to inspect parameters</span>
          </div>

          <div className="py-8 px-4 flex flex-col md:flex-row items-center justify-between gap-4 relative overflow-x-auto">
            {nodes.map((n, idx) => {
              const Icon = n.icon;
              const isSelected = selectedNodeId === n.id;
              const isDep = deployedNodes[n.id];
              const isWeakestLink = n.id === 'node-2';
              const isSeveredByWhatIf = whatIfFix && isWeakestLink;

              return (
                <React.Fragment key={n.id}>
                  <div
                    onClick={() => setSelectedNodeId(n.id)}
                    className={`cursor-pointer p-4 rounded-xl border flex flex-col items-center text-center w-36 transition-all duration-300 transform hover:scale-105 relative ${
                      isSeveredByWhatIf
                        ? 'border-2 border-dashed border-emerald-400 bg-emerald-950/40 ring-2 ring-emerald-500/30'
                        : isDep
                        ? 'border-emerald-500 text-emerald-400 bg-emerald-950/40'
                        : isWeakestLink
                        ? 'border-rose-500 text-rose-400 bg-rose-950/40 glow-red ring-1 ring-rose-500/60'
                        : n.color
                    } ${
                      isSelected ? 'ring-2 ring-cyan-400 ring-offset-2 ring-offset-slate-950 scale-105' : ''
                    }`}
                  >
                    {isWeakestLink && !isDep && (
                      <span className="absolute -top-2 px-1.5 py-0.5 rounded-full text-[8px] font-bold font-mono bg-rose-600 text-slate-950 animate-pulse tracking-tight">
                        WEAKEST LINK
                      </span>
                    )}

                    {isSeveredByWhatIf && (
                      <span className="absolute -top-2 px-1.5 py-0.5 rounded-full text-[8px] font-bold font-mono bg-emerald-500 text-slate-950 tracking-tight">
                        SEVERED
                      </span>
                    )}

                    <div className="p-2.5 rounded-full bg-slate-900 border border-slate-700 mb-2">
                      <Icon className="w-6 h-6" />
                    </div>
                    <div className="text-xs font-bold text-slate-100">{n.title}</div>
                    <div className="text-[10px] font-mono mt-1 text-slate-400 truncate w-full">{n.subtitle}</div>
                    <div className="mt-2 text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 border border-slate-800">
                      {isDep ? '✓ Mitigated' : isSeveredByWhatIf ? '✓ Severed' : `Risk: +${n.risk}`}
                    </div>
                  </div>

                  {idx < nodes.length - 1 && (
                    <div className="hidden md:flex items-center text-slate-600">
                      {whatIfFix && idx === 1 ? (
                        <div className="px-1 text-[10px] font-mono font-bold text-emerald-400 border border-emerald-700 bg-emerald-950 rounded">
                          SEVERED ✕
                        </div>
                      ) : (
                        <ArrowRight className="w-6 h-6 animate-pulse text-cyan-500" />
                      )}
                    </div>
                  )}
                </React.Fragment>
              );
            })}
          </div>

          <div className="p-3.5 sm:p-4 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-400 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 font-mono">
            <div className="flex items-center space-x-2">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-ping"></span>
              <span>Identified Chokepoint: <strong className="text-slate-200">Identity Provider (Okta / Azure AD SSO)</strong></span>
            </div>
            <span className="text-rose-400 font-bold shrink-0">+25 Risk Contribution</span>
          </div>
        </div>

        {/* Selected Node Details Drawer */}
        <div className="glass-panel p-6 rounded-2xl border border-cyan-500/30 space-y-6">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400 shrink-0" />
              <span>NODE INSPECTION PANEL</span>
            </h3>
            <span className="text-xs font-mono text-cyan-400 shrink-0">{selectedNode.type}</span>
          </div>

          <div>
            <div className="flex items-center space-x-2">
              <h4 className="text-lg font-bold text-slate-100">{selectedNode.title}</h4>
              {selectedNode.id === 'node-2' && (
                <span className="px-2 py-0.5 rounded text-[9px] font-bold font-mono bg-rose-950 text-rose-300 border border-rose-800 animate-pulse">
                  CRITICAL CHOKEPOINT
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 mt-0.5">{selectedNode.subtitle}</p>
          </div>

          <div className="grid grid-cols-2 gap-3 font-mono text-xs">
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 min-w-0">
              <div className="text-[10px] text-slate-500 uppercase truncate">Exploitability</div>
              <div className="text-sm font-bold text-rose-400 mt-0.5 truncate">{selectedNode.exploitability}</div>
            </div>
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 min-w-0">
              <div className="text-[10px] text-slate-500 uppercase truncate">Potential Impact</div>
              <div className="text-sm font-bold text-rose-400 mt-0.5 truncate">{selectedNode.impact}</div>
            </div>
          </div>

          <div className="space-y-3 text-xs">
            <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
              <div className="text-[10px] font-mono text-slate-500 uppercase">Exploit Reason</div>
              <p className="text-slate-300">{selectedNode.reason}</p>
            </div>

            <div className="p-3.5 rounded-xl bg-cyan-950/40 border border-cyan-800/80 space-y-2">
              <div className="text-[10px] font-mono text-cyan-400 uppercase font-bold">Recommended Control</div>
              <p className="text-slate-100 font-semibold">{selectedNode.control}</p>

              {isCurrentDeployed ? (
                <div className="flex items-center space-x-1 text-emerald-400 font-mono text-xs font-bold pt-1">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Control Deployed & Mitigated</span>
                </div>
              ) : (
                <button
                  onClick={() => handleDeployNodeControl(selectedNode.id)}
                  className="w-full py-2.5 mt-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center justify-center space-x-1.5 glow-cyan"
                >
                  <Zap className="w-3.5 h-3.5 fill-slate-950" />
                  <span>Deploy Control to Node</span>
                </button>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
