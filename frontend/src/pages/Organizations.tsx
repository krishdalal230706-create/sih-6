import React from 'react';
import { Building2, ShieldAlert, CheckCircle2, ArrowRight } from 'lucide-react';
import { useApp } from '../context/AppContext';

export const Organizations: React.FC = () => {
  const { organizations, switchOrg, activeOrg } = useApp();

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 sm:space-y-8 max-w-7xl mx-auto">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-100 uppercase">ORGANIZATION MANAGEMENT</h1>
          <p className="text-xs text-slate-400 mt-1">
            Multi-tenant organizational posture, threat pattern sharing statistics, and security baseline controls.
          </p>
        </div>

        <span className="font-mono text-xs text-cyan-400">5 Registered Organizations</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {organizations.map((org) => {
          const isActive = activeOrg?.id === org.id;
          return (
            <div
              key={org.id}
              className={`glass-panel p-6 rounded-2xl border transition-all space-y-4 ${
                isActive ? 'border-cyan-500 shadow-lg shadow-cyan-950/40' : 'border-slate-800'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-800">
                    <Building2 className="w-5 h-5 text-cyan-400" />
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-slate-100">{org.name}</h3>
                    <div className="text-[10px] font-mono text-slate-400">{org.type}</div>
                  </div>
                </div>

                <span
                  className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${
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

              <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                  <div className="text-[10px] text-slate-500 uppercase">Users</div>
                  <div className="text-slate-200 font-bold mt-0.5">{org.usersCount.toLocaleString()}</div>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                  <div className="text-[10px] text-slate-500 uppercase">Critical Systems</div>
                  <div className="text-slate-200 font-bold mt-0.5">{org.criticalSystems}</div>
                </div>
              </div>

              <button
                onClick={() => switchOrg(org.id)}
                className={`w-full py-2 rounded-xl text-xs font-bold font-mono transition-all ${
                  isActive
                    ? 'bg-cyan-950 text-cyan-400 border border-cyan-800'
                    : 'bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800'
                }`}
              >
                {isActive ? '● Active Context' : 'Switch Context'}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
};
