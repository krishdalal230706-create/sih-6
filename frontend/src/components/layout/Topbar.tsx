import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Building2,
  Bell,
  Activity,
  ShieldAlert,
  Sparkles,
  CheckCircle2,
  BellRing,
  Menu,
  RotateCcw,
  User,
  LogOut,
  AlertTriangle,
  Database,
  Radio,
  ExternalLink,
  Trash2,
  Check,
  Sun,
  Moon
} from 'lucide-react';
import { useApp } from '../../context/AppContext';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import { api } from '../../api/client';

interface TopbarProps {
  onMenuToggle?: () => void;
}

export const Topbar: React.FC<TopbarProps> = ({ onMenuToggle }) => {
  const {
    activeOrg,
    startDemo,
    isDemoActive,
    resetDemoBaseline,
    riskData,
    notifications,
    unreadCount,
    markNotificationRead,
    markAllNotificationsRead,
    clearNotifications
  } = useApp();

  const { currentUser, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const [isNotifOpen, setIsNotifOpen] = useState(false);
  const [isUserMenuOpen, setIsUserMenuOpen] = useState(false);
  const [isDemoMode, setIsDemoMode] = useState(false);
  const navigate = useNavigate();

  const notifRef = useRef<HTMLDivElement>(null);
  const userMenuRef = useRef<HTMLDivElement>(null);

  // Check backend DEMO_MODE availability for Demo controls
  useEffect(() => {
    api.get<{ demoUsers: any[] }>('/api/auth/demo-users')
      .then((res) => {
        if (res && res.demoUsers && res.demoUsers.length > 0) {
          setIsDemoMode(true);
        }
      })
      .catch(() => {
        setIsDemoMode(false);
      });
  }, []);

  // Close panels when clicking outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setIsNotifOpen(false);
      }
      if (userMenuRef.current && !userMenuRef.current.contains(e.target as Node)) {
        setIsUserMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleSignOut = async () => {
    await logout();
    navigate('/login');
  };

  const getNotifIcon = (type: string) => {
    switch (type) {
      case 'ALERT':
        return <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />;
      case 'THREAT':
        return <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />;
      case 'LEDGER':
        return <Database className="w-4 h-4 text-cyan-400 shrink-0" />;
      case 'WARNING':
        return <Radio className="w-4 h-4 text-amber-400 shrink-0" />;
      case 'RISK':
        return <Activity className="w-4 h-4 text-rose-400 shrink-0" />;
      case 'SUCCESS':
        return <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />;
      default:
        return <Bell className="w-4 h-4 text-cyan-400 shrink-0" />;
    }
  };

  const getNotifBg = (type: string, read: boolean) => {
    if (read) return '';
    switch (type) {
      case 'ALERT': return 'bg-rose-950/20 border-l-2 border-rose-400';
      case 'THREAT': return 'bg-amber-950/20 border-l-2 border-amber-400';
      case 'SUCCESS': return 'bg-emerald-950/20 border-l-2 border-emerald-400';
      case 'LEDGER': return 'bg-cyan-950/20 border-l-2 border-cyan-400';
      default: return 'bg-cyan-950/20 border-l-2 border-cyan-400';
    }
  };

  // Severity calculation rule: >=80 Critical, >=65 High, >=45 Medium, else Low
  const currentRiskScore = riskData?.overallRiskScore ?? activeOrg?.riskScore ?? 42;
  const severityBadge = (() => {
    if (currentRiskScore >= 80) {
      return {
        label: 'CRITICAL',
        badgeClass: 'bg-rose-950/80 text-rose-400 border-rose-800/60',
        textClass: 'text-rose-400'
      };
    }
    if (currentRiskScore >= 65) {
      return {
        label: 'HIGH',
        badgeClass: 'bg-orange-950/80 text-orange-400 border-orange-800/60',
        textClass: 'text-orange-400'
      };
    }
    if (currentRiskScore >= 45) {
      return {
        label: 'MEDIUM',
        badgeClass: 'bg-amber-950/80 text-amber-400 border-amber-800/60',
        textClass: 'text-amber-400'
      };
    }
    return {
      label: 'LOW',
      badgeClass: 'bg-emerald-950/80 text-emerald-400 border-emerald-800/60',
      textClass: 'text-emerald-400'
    };
  })();

  const getOrgDisplayName = (orgId?: string) => {
    switch (orgId) {
      case 'org-1':
        return 'Bank A (Financial Services)';
      case 'org-2':
        return 'Hospital B (Healthcare)';
      case 'org-3':
        return 'University C (Education)';
      default:
        return activeOrg?.name || 'Institutional SOC';
    }
  };

  return (
    <header className="h-16 bg-[#0F1420]/80 backdrop-blur-md border-b border-slate-800/80 px-3 sm:px-6 flex items-center justify-between sticky top-0 z-20">
      {/* Left: Mobile Toggle & Static Scoped Organization Banner */}
      <div className="flex items-center space-x-2 sm:space-x-4">
        {/* Mobile Hamburger Toggle */}
        <button
          onClick={onMenuToggle}
          className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-cyan-400 lg:hidden"
          title="Toggle Navigation Menu"
          aria-label="Open menu"
        >
          <Menu className="w-5 h-5" />
        </button>

        {/* Static Institutional Name (No Cross-Tenant Switcher) */}
        <div className="flex items-center space-x-2.5 px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-700/80 text-slate-200 text-xs font-medium">
          <Building2 className="w-4 h-4 text-cyan-400 shrink-0" />
          <span className="font-semibold truncate text-slate-100">
            {getOrgDisplayName(currentUser?.orgId)}
          </span>
          <span className="text-[9px] bg-cyan-950 text-cyan-400 border border-cyan-800/60 px-1.5 py-0.5 rounded font-mono uppercase">
            SOC Scoped
          </span>
        </div>

        {/* Operational Status Indicator */}
        <div className="hidden xl:flex items-center space-x-2 text-xs font-mono text-slate-400">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
          <span>System Status: <strong className="text-emerald-400">Operational</strong></span>
        </div>
      </div>

      {/* Right Controls: Dynamic Risk Badge, Demo Controls, Bell, and User Menu */}
      <div className="flex items-center space-x-2 sm:space-x-3">
        {/* Shared Dynamic Risk Indicator */}
        <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800">
          <ShieldAlert className={`w-4 h-4 ${severityBadge.textClass}`} />
          <span className="text-xs text-slate-400 font-medium hidden sm:inline">Risk Score:</span>
          <span className={`text-xs font-mono font-bold ${severityBadge.textClass}`}>
            {currentRiskScore}/100
          </span>
          <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono border uppercase font-bold ${severityBadge.badgeClass}`}>
            {severityBadge.label}
          </span>
        </div>

        {/* Demo Mode Button (Appears ONLY when DEMO_MODE is true) */}
        {isDemoMode && (
          <>
            <button
              id="launch-demo-btn"
              onClick={startDemo}
              className={`flex items-center space-x-1.5 px-2.5 sm:px-3.5 py-1.5 rounded-lg font-medium text-xs tracking-wide transition-all duration-300 shadow-lg ${
                isDemoActive
                  ? 'bg-gradient-to-r from-amber-500 to-orange-600 text-slate-950 ring-2 ring-amber-400/50 shadow-amber-500/20'
                  : 'bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-bold shadow-cyan-500/25'
              }`}
            >
              <Sparkles className="w-3.5 h-3.5 animate-spin-slow shrink-0" />
              <span className="hidden sm:inline">{isDemoActive ? 'DEMO ACTIVE' : 'LAUNCH DEMO'}</span>
              <span className="sm:hidden">DEMO</span>
            </button>

            <button
              id="reset-demo-baseline-btn"
              onClick={() => resetDemoBaseline()}
              className="flex items-center space-x-1 px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-cyan-500/50 text-slate-400 hover:text-cyan-300 transition-colors text-xs font-mono"
              title="Reset Demo Baseline"
            >
              <RotateCcw className="w-3.5 h-3.5 shrink-0" />
              <span className="hidden xl:inline">RESET</span>
            </button>
          </>
        )}

        {/* Quick Dark/Light Mode Toggle */}
        <button
          id="quick-theme-toggle-btn"
          type="button"
          onClick={toggleTheme}
          className="p-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-cyan-500/50 text-slate-400 hover:text-slate-200 transition-colors"
          title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Mode`}
          aria-label="Toggle theme mode"
        >
          {theme === 'dark' ? (
            <Sun className="w-4 h-4 text-amber-400" />
          ) : (
            <Moon className="w-4 h-4 text-cyan-400" />
          )}
        </button>

        {/* Interactive Notification Bell */}
        <div className="relative" ref={notifRef}>
          <button
            id="notif-bell-btn"
            onClick={() => {
              setIsNotifOpen(!isNotifOpen);
              setIsUserMenuOpen(false);
            }}
            className="relative p-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-cyan-500/50 text-slate-400 hover:text-slate-200 transition-colors"
            title="Notifications Center"
          >
            {unreadCount > 0 ? (
              <BellRing className="w-4 h-4 text-cyan-400" />
            ) : (
              <Bell className="w-4 h-4" />
            )}
            {unreadCount > 0 && (
              <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-rose-500 text-slate-950 font-mono text-[10px] font-bold flex items-center justify-center animate-pulse">
                {unreadCount > 9 ? '9+' : unreadCount}
              </span>
            )}
          </button>

          {/* Notifications Dropdown Panel */}
          {isNotifOpen && (
            <div className="absolute top-full right-0 mt-2 w-[calc(100vw-2rem)] max-w-sm sm:w-96 bg-[#0F1420] border border-slate-700 rounded-2xl shadow-2xl z-50 overflow-hidden text-slate-100 animate-fadeIn">
              <div className="p-3.5 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
                <div className="flex items-center space-x-2">
                  <Bell className="w-4 h-4 text-cyan-400" />
                  <span className="text-xs font-bold uppercase tracking-wider">Live Security Alerts</span>
                </div>
                <div className="flex items-center space-x-1.5">
                  {unreadCount > 0 && (
                    <button
                      onClick={markAllNotificationsRead}
                      className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-cyan-400 transition-colors"
                      title="Mark all as read"
                    >
                      <Check className="w-3.5 h-3.5" />
                    </button>
                  )}
                  {notifications.length > 0 && (
                    <button
                      onClick={clearNotifications}
                      className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-rose-400 transition-colors"
                      title="Clear notifications"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              </div>

              <div className="max-h-80 overflow-y-auto divide-y divide-slate-800/50">
                {notifications.length === 0 ? (
                  <div className="p-8 text-center text-xs text-slate-500">
                    No active threat notifications. Institutional posture secure.
                  </div>
                ) : (
                  notifications.map((n) => (
                    <div
                      key={n.id}
                      onClick={() => {
                        markNotificationRead(n.id);
                        if (n.link) {
                          navigate(n.link);
                          setIsNotifOpen(false);
                        }
                      }}
                      className={`p-3.5 hover:bg-slate-900/80 transition-colors cursor-pointer flex items-start space-x-3 text-xs ${getNotifBg(n.type, n.read)} ${!n.read ? '' : 'opacity-60'}`}
                    >
                      <div className="mt-0.5">{getNotifIcon(n.type)}</div>
                      <div className="flex-1 space-y-0.5 min-w-0">
                        <div className="flex items-center justify-between gap-2">
                          <span className={`font-bold truncate ${n.read ? 'text-slate-400' : 'text-slate-200'}`}>{n.title}</span>
                          <span className="text-[10px] font-mono text-slate-500 shrink-0">{n.time}</span>
                        </div>
                        <p className="text-[11px] text-slate-400 leading-normal">{n.message}</p>
                        {n.link && (
                          <div className="text-[10px] font-mono text-cyan-400 flex items-center space-x-1 pt-1">
                            <span>Inspect alert</span>
                            <ExternalLink className="w-3 h-3" />
                          </div>
                        )}
                      </div>
                      {!n.read && (
                        <span className="w-2 h-2 rounded-full bg-cyan-400 shrink-0 mt-1.5"></span>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        {/* User Account Menu with Sign Out */}
        <div className="relative" ref={userMenuRef}>
          <button
            onClick={() => {
              setIsUserMenuOpen(!isUserMenuOpen);
              setIsNotifOpen(false);
            }}
            className="flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-cyan-500/50 text-slate-300 text-xs transition-colors"
            title="User Account Menu"
          >
            <User className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden sm:inline font-medium">{currentUser?.name?.split(' ')[0] || 'Admin'}</span>
            <span className="text-[9px] font-mono px-1 rounded uppercase bg-cyan-950 text-cyan-400 border border-cyan-800">
              {currentUser?.role || 'ADMIN'}
            </span>
          </button>

          {isUserMenuOpen && (
            <div className="absolute top-full right-0 mt-2 w-56 bg-[#0F1420] border border-slate-700 rounded-xl shadow-2xl z-50 overflow-hidden py-1 animate-fadeIn">
              <div className="px-3.5 py-2.5 border-b border-slate-800">
                <div className="font-semibold text-xs text-white truncate">{currentUser?.name}</div>
                <div className="text-[10px] font-mono text-slate-400 truncate">{currentUser?.email}</div>
                <div className="text-[10px] font-mono text-cyan-400 pt-1">{getOrgDisplayName(currentUser?.orgId)}</div>
              </div>

              <div className="p-1">
                <button
                  onClick={handleSignOut}
                  className="w-full flex items-center space-x-2 px-3 py-2 text-xs text-rose-300 hover:bg-rose-950/40 rounded-lg transition-colors text-left font-medium"
                >
                  <LogOut className="w-3.5 h-3.5 text-rose-400" />
                  <span>Sign Out</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
