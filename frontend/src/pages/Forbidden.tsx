import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldAlert, ArrowLeft, Home, UserCheck } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const Forbidden: React.FC = () => {
  const { currentUser } = useAuth();
  const navigate = useNavigate();

  const handleReturn = () => {
    if (currentUser?.role === 'user') {
      navigate('/my-account');
    } else {
      navigate('/');
    }
  };

  return (
    <div className="min-h-screen bg-[#0B0F17] text-slate-100 flex flex-col justify-center items-center px-4 relative overflow-hidden">
      {/* Background Glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-rose-500/10 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-lg bg-[#0F1420] border border-rose-900/50 rounded-2xl p-8 shadow-2xl relative z-10 text-center">
        <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-rose-950/60 border border-rose-500/40 p-2 shadow-lg shadow-rose-950/50 mb-5">
          <ShieldAlert className="w-8 h-8 text-rose-400" />
        </div>

        <div className="inline-block px-3 py-1 rounded-full bg-rose-950/80 border border-rose-800 text-rose-300 font-mono text-xs mb-3">
          HTTP 403 • ACCESS RESTRICTED
        </div>

        <h1 className="text-2xl font-bold tracking-tight text-white mb-2">
          Administrative Boundary Enforced
        </h1>

        <p className="text-sm text-slate-400 leading-relaxed mb-6">
          Your active session lacks authorization to access this institutional SOC resource or cross-tenant endpoint. Security policies restrict cross-organizational and unprivileged access.
        </p>

        <div className="bg-[#0B0F17] rounded-xl p-4 border border-slate-800/80 mb-6 text-left text-xs space-y-2 font-mono">
          <div className="flex justify-between text-slate-400">
            <span>Current Role:</span>
            <span className="text-cyan-400 font-bold uppercase">{currentUser?.role || 'ANONYMOUS'}</span>
          </div>
          <div className="flex justify-between text-slate-400">
            <span>Assigned Organization:</span>
            <span className="text-slate-200">{currentUser?.orgId || 'None'}</span>
          </div>
          <div className="flex justify-between text-slate-400">
            <span>Enforcement Engine:</span>
            <span className="text-emerald-400">Multi-Tenant RBAC & Org Isolation</span>
          </div>
        </div>

        <div className="flex items-center justify-center space-x-3">
          <button
            onClick={handleReturn}
            className="flex items-center space-x-2 px-5 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-semibold text-xs rounded-lg shadow-lg shadow-cyan-500/20 transition-all"
          >
            {currentUser?.role === 'user' ? <UserCheck className="w-4 h-4" /> : <Home className="w-4 h-4" />}
            <span>{currentUser?.role === 'user' ? 'Return to My Account' : 'Return to Overview'}</span>
          </button>
        </div>
      </div>
    </div>
  );
};

