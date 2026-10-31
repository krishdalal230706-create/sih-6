import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Home, ArrowLeft } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const NotFound: React.FC = () => {
  const { currentUser, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  const handleReturn = () => {
    if (!isAuthenticated) {
      navigate('/login');
    } else if (currentUser?.role === 'user') {
      navigate('/my-account');
    } else {
      navigate('/');
    }
  };

  return (
    <div className="min-h-screen bg-[#0B0F17] text-slate-100 flex flex-col justify-center items-center px-4 relative overflow-hidden">
      {/* Background Glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-md bg-[#0F1420] border border-slate-800 rounded-2xl p-8 shadow-2xl relative z-10 text-center">
        <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-cyan-950/60 border border-cyan-500/40 p-2 shadow-lg shadow-cyan-950/50 mb-5">
          <Search className="w-8 h-8 text-cyan-400" />
        </div>

        <div className="inline-block px-3 py-1 rounded-full bg-slate-800 border border-slate-700 text-slate-400 font-mono text-xs mb-3">
          HTTP 404 • ROUTE NOT FOUND
        </div>

        <h1 className="text-2xl font-bold tracking-tight text-white mb-2">
          Unknown Security Endpoint
        </h1>

        <p className="text-sm text-slate-400 leading-relaxed mb-6">
          The requested URL path does not correspond to an active portal route or SOC capability within the grid.
        </p>

        <button
          onClick={handleReturn}
          className="inline-flex items-center space-x-2 px-5 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-semibold text-xs rounded-lg shadow-lg shadow-cyan-500/20 transition-all"
        >
          <Home className="w-4 h-4" />
          <span>Return to Dashboard</span>
        </button>
      </div>
    </div>
  );
};

