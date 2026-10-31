import React from 'react';
import { Navigate, Outlet, useNavigate } from 'react-router-dom';
import { ShieldCheck, LogOut, Building2, User } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

export const UserLayout: React.FC = () => {
  const { currentUser, isAuthenticated, isLoadingAuth, logout } = useAuth();
  const navigate = useNavigate();

  if (isLoadingAuth) {
    return (
      <div className="min-h-screen bg-[#0B0F17] flex items-center justify-center">
        <div className="flex flex-col items-center space-y-3">
          <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
          <span className="text-xs font-mono text-slate-400">Verifying security session...</span>
        </div>
      </div>
    );
  }

  if (!isAuthenticated || !currentUser) {
    return <Navigate to="/login" replace />;
  }

  const handleSignOut = async () => {
    await logout();
    navigate('/login');
  };

  const getOrgDisplayName = (orgId: string) => {
    switch (orgId) {
      case 'org-1':
        return 'Bank A (Financial Services)';
      case 'org-2':
        return 'Hospital B (Healthcare)';
      case 'org-3':
        return 'University C (Education)';
      default:
        return orgId;
    }
  };

  return (
    <div className="min-h-screen bg-[#0B0F17] text-slate-100 flex flex-col font-sans">
      {/* Minimal User Portal Header */}
      <header className="h-16 bg-[#0F1420] border-b border-slate-800 px-4 sm:px-6 flex items-center justify-between sticky top-0 z-30">
        <div className="flex items-center space-x-3">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 p-0.5 shadow-md shadow-cyan-500/20">
            <div className="w-full h-full bg-[#0B0F17] rounded-[10px] flex items-center justify-center">
              <ShieldCheck className="w-5 h-5 text-cyan-400" />
            </div>
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold tracking-wider text-sm uppercase text-slate-100">
                CYBERGUARD <span className="text-cyan-400">GRID</span>
              </span>
              <span className="text-[10px] bg-cyan-950/60 text-cyan-400 border border-cyan-800/60 px-2 py-0.5 rounded-full font-mono">
                User Portal
              </span>
            </div>
            <div className="flex items-center space-x-1.5 text-[11px] text-slate-400">
              <Building2 className="w-3 h-3 text-slate-500" />
              <span>{getOrgDisplayName(currentUser.orgId)}</span>
            </div>
          </div>
        </div>

        {/* User Status & Sign Out */}
        <div className="flex items-center space-x-3">
          <div className="hidden sm:flex items-center space-x-2 bg-slate-900/80 border border-slate-800 rounded-lg px-3 py-1.5 text-xs">
            <User className="w-3.5 h-3.5 text-slate-400" />
            <span className="font-medium text-slate-200">{currentUser.name}</span>
            <span className="text-[10px] text-slate-500 font-mono">({currentUser.email})</span>
          </div>

          <button
            onClick={handleSignOut}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800/80 hover:bg-rose-950/40 hover:border-rose-800/60 border border-slate-700/60 text-slate-300 hover:text-rose-300 rounded-lg text-xs font-medium transition-all"
            title="Sign out of your account"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Sign Out</span>
          </button>
        </div>
      </header>

      {/* Main Page Body */}
      <main className="flex-1 overflow-y-auto">
        <Outlet />
      </main>
    </div>
  );
};

