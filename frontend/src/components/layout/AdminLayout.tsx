import React, { useState } from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { Sidebar } from './Sidebar';
import { Topbar } from './Topbar';
import { DemoModeController } from '../demo/DemoModeController';

export const AdminLayout: React.FC = () => {
  const { currentUser, isAuthenticated, isLoadingAuth } = useAuth();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  if (isLoadingAuth) {
    return (
      <div className="min-h-screen bg-[#0B0F17] flex items-center justify-center">
        <div className="flex flex-col items-center space-y-3">
          <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
          <span className="text-xs font-mono text-slate-400">Loading institutional SOC environment...</span>
        </div>
      </div>
    );
  }

  // If unauthenticated, redirect to login
  if (!isAuthenticated || !currentUser) {
    return <Navigate to="/login" replace />;
  }

  // If standard user attempts to view Admin SOC, redirect to User Portal
  if (currentUser.role === 'user') {
    return <Navigate to="/my-account" replace />;
  }

  return (
    <div className="flex h-screen bg-[#0B0F17] text-slate-100 font-sans overflow-hidden">
      {/* Left Navigation Sidebar */}
      <Sidebar isOpen={isMobileMenuOpen} onClose={() => setIsMobileMenuOpen(false)} />

      {/* Main Content Workspace */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden relative">
        {/* Top Bar */}
        <Topbar onMenuToggle={() => setIsMobileMenuOpen(!isMobileMenuOpen)} />

        {/* Scrollable Page Body */}
        <main className="flex-1 overflow-y-auto pb-24">
          <Outlet />
        </main>

        {/* Interactive Demo Mode Floating Controller */}
        <DemoModeController />
      </div>
    </div>
  );
};

