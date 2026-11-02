import React from 'react';
import { Building2, ShieldAlert, CheckCircle2, ArrowRight, Landmark, ShieldCheck, Globe, Users, Server, Lock } from 'lucide-react';
import { useApp } from '../context/AppContext';

export const Organizations: React.FC = () => {
  const { organizations, switchOrg, activeOrg } = useApp();

  const demoBank = organizations.find((o) => o.id === 'org-1') || activeOrg || {
    id: 'org-1',
    name: 'Demo Bank',
    type: 'Banking and Financial Services',
    country: 'India',
    usersCount: 12500,
    criticalSystems: 10,
    riskScore: 84
  };

  const peerNodes = organizations.filter((o) => o.id !== 'org-1');

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 sm:space-y-8 max-w-7xl mx-auto">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-100 uppercase">
              ORGANIZATION PROFILE & MESH IDENTITY
            </h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-mono bg-cyan-950 text-cyan-400 border border-cyan-800">
              Banking Edition
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Dedicated Bank SOC posture, regulatory compliance boundaries & external threat mesh sharing federations.
          </p>
        </div>

        <span className="font-mono text-xs text-cyan-400">Primary Tenant: Demo Bank (org-1)</span>
      </div>

      {/* Primary Organization Focus Card: Demo Bank */}
      <div className="glass-panel p-6 rounded-2xl border-2 border-cyan-500/60 bg-gradient-to-br from-[#0F1420] via-[#121a2d] to-[#0F1420] shadow-2xl space-y-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-5">
          <div className="flex items-center space-x-4">
            <div className="p-3.5 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-lg shadow-cyan-500/20">
              <Landmark className="w-8 h-8" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-xl font-black text-white">{demoBank.name}</h2>
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                  ● ACTIVE MANAGED TENANT
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Scheduled Commercial Bank • Banking and Financial Services (BFSI) • Republic of India
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="px-4 py-2 rounded-xl bg-slate-900 border border-slate-800 text-right">
              <div className="text-[10px] font-mono text-slate-500 uppercase">Bank Risk Index</div>
              <div className="text-xl font-black font-mono text-rose-400">{demoBank.riskScore} / 100</div>
            </div>
          </div>
        </div>

        {/* Detailed Metrics Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
          <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800">
            <div className="text-[10px] text-slate-500 uppercase flex items-center gap-1.5">
              <Users className="w-3.5 h-3.5 text-cyan-400" />
              <span>Bank Workforce</span>
            </div>
            <div className="text-slate-100 font-bold text-base mt-1">
              {(demoBank.usersCount || 12500).toLocaleString()} Users
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5">Branch Tellers & Admin Staff</div>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800">
            <div className="text-[10px] text-slate-500 uppercase flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-purple-400" />
              <span>Monitored Assets</span>
            </div>
            <div className="text-slate-100 font-bold text-base mt-1">10 Tier-1 Systems</div>
            <div className="text-[10px] text-slate-400 mt-0.5">Finacle CBS, UPI Switch, ATM</div>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800">
            <div className="text-[10px] text-slate-500 uppercase flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-yellow-400" />
              <span>Authentication Controls</span>
            </div>
            <div className="text-slate-100 font-bold text-base mt-1">FIDO2 & Hardware HSM</div>
            <div className="text-[10px] text-slate-400 mt-0.5">Thales Luna & Keycloak PKI</div>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800">
            <div className="text-[10px] text-slate-500 uppercase flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5 text-emerald-400" />
              <span>Regulatory Scope</span>
            </div>
            <div className="text-slate-100 font-bold text-base mt-1">India BFSI Framework</div>
            <div className="text-[10px] text-slate-400 mt-0.5">Cyber Security Framework (CSITE)</div>
          </div>
        </div>
      </div>

      {/* External Threat Mesh Federation Nodes (Zero-Knowledge) */}
      <div className="space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-2">
          <div>
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              External Threat Mesh Partners (Zero-Knowledge Anonymized)
            </h3>
            <p className="text-xs text-slate-400">
              Federated peer nodes exchanging sanitized threat hashes via DLT trust ledger. Internal banking data never leaves Demo Bank.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {peerNodes.map((org) => (
            <div key={org.id} className="p-4 rounded-xl bg-slate-900/70 border border-slate-800/80 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-300">{org.name}</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                  External Node
                </span>
              </div>
              <div className="text-[11px] text-slate-400 font-mono">{org.type}</div>
              <div className="text-[10px] text-cyan-400/80 flex items-center gap-1 pt-1 border-t border-slate-800">
                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                <span>Zero-Knowledge DLT Mesh Active</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
