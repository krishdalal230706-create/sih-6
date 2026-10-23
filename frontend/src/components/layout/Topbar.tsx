import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Building2,
  ChevronDown,
  Play,
  Bell,
  Search,
  Activity,
  ShieldAlert,
  Sparkles,
  X,
  Check,
  Trash2,
  ExternalLink,
  AlertTriangle,
  Database,
  Radio,
  CheckCircle2,
  BellRing,
  Menu,
  RotateCcw
} from 'lucide-react';
import { useApp } from '../../context/AppContext';

interface TopbarProps {
  onMenuToggle?: () => void;
}

export const Topbar: React.FC<TopbarProps> = ({ onMenuToggle }) => {
  const {
    activeOrg,
    organizations,
    switchOrg,
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

  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  const [isNotifOpen, setIsNotifOpen] = useState(false);
  const navigate = useNavigate();

  const dropdownRef = useRef<HTMLDivElement>(null);
  const notifRef = useRef<HTMLDivElement>(null);

  // Close panels when clicking outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setIsDropdownOpen(false);
      }
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setIsNotifOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

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

  return (
    <header className="h-16 bg-[#0F1420]/80 backdrop-blur-md border-b border-slate-800/80 px-3 sm:px-6 flex items-center justify-between sticky top-0 z-20">
      {/* Left: Mobile Toggle & Organization Switcher */}
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

        <div className="relative" ref={dropdownRef}>
          <button
            id="org-switcher-btn"
            onClick={() => {
              setIsDropdownOpen(!isDropdownOpen);
              setIsNotifOpen(false);
            }}
            className="flex items-center space-x-2 sm:space-x-3 px-2.5 sm:px-3.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700/80 hover:border-cyan-500/50 text-slate-200 transition-all text-xs font-medium max-w-[160px] sm:max-w-xs"
          >
            <Building2 className="w-4 h-4 text-cyan-400 shrink-0" />
            <span className="font-semibold truncate">{activeOrg?.name || 'Select Organization'}</span>
            <ChevronDown className={`w-3.5 h-3.5 text-slate-400 shrink-0 transition-transform ${isDropdownOpen ? 'rotate-180' : ''}`} />
          </button>

          {isDropdownOpen && (
            <div className="absolute top-full left-0 mt-2 w-64 bg-slate-900 border border-slate-800 rounded-xl shadow-2xl z-50 overflow-hidden py-1">
              <div className="px-3 py-2 text-[10px] font-mono text-slate-500 uppercase tracking-wider border-b border-slate-800">
                Switch Organization Context
              </div>
              {organizations.map((org) => (
                <button
                  key={org.id}
                  id={`org-switch-${org.id}`}
                  onClick={() => {
                    switchOrg(org.id);
                    setIsDropdownOpen(false);
                  }}
                  className={`w-full px-3 py-2.5 text-left text-xs flex items-center justify-between hover:bg-slate-800/80 transition-colors ${
                    activeOrg?.id === org.id ? 'bg-cyan-950/40 text-cyan-400 font-semibold' : 'text-slate-300'
                  }`}
                >
                  <div className="truncate">
                    <div className="truncate font-medium">{org.name}</div>
                    <div className="text-[10px] text-slate-500 truncate">{org.type}</div>
                  </div>
                  <span
                    className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ml-2 shrink-0 ${
                      org.riskScore >= 80
                        ? 'bg-rose-950 text-rose-400 border-rose-800'
                        : org.riskScore >= 65
                        ? 'bg-amber-950 text-amber-400 border-amber-800'
                        : 'bg-emerald-950 text-emerald-400 border-emerald-800'
                    }`}
                  >
                    {org.riskScore} RS
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Operational Status */}
        <div className="hidden xl:flex items-center space-x-2 text-xs font-mono text-slate-400">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
          <span>System Status: <strong className="text-emerald-400">Operational</strong></span>
        </div>
      </div>

      {/* Right Controls & Demo Mode Button */}
      <div className="flex items-center space-x-2 sm:space-x-4">
        {/* Dynamic Risk Indicator */}
        <div className="hidden lg:flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800">
          <ShieldAlert className="w-4 h-4 text-rose-400" />
          <span className="text-xs text-slate-400 font-medium">Risk Score:</span>
          <span className="text-xs font-mono font-bold text-rose-400">
            {riskData?.overallRiskScore ?? activeOrg?.riskScore ?? 84}/100
          </span>
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-950/80 text-rose-400 font-mono border border-rose-800/60 uppercase">
            {riskData?.severity ?? 'CRITICAL'}
          </span>
        </div>

        {/* Demo Mode Button */}
        <button
          id="launch-demo-btn"
          onClick={startDemo}
          className={`flex items-center space-x-1.5 sm:space-x-2 px-2.5 sm:px-4 py-2 rounded-lg font-medium text-xs tracking-wide transition-all duration-300 shadow-lg ${
            isDemoActive
              ? 'bg-gradient-to-r from-amber-500 to-orange-600 text-slate-950 ring-2 ring-amber-400/50 shadow-amber-500/20'
              : 'bg-gradient-to-r from-cyan-500 via-blue-600 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-bold shadow-cyan-500/25 glow-cyan'
          }`}
        >
          <Sparkles className="w-3.5 h-3.5 sm:w-4 sm:h-4 animate-spin-slow shrink-0" />
          <span className="hidden sm:inline">{isDemoActive ? 'DEMO ACTIVE' : 'LAUNCH DEMO'}</span>
          <span className="sm:hidden">DEMO</span>
        </button>

        {/* Reset Demo Baseline Button */}
        <button
          id="reset-demo-baseline-btn"
          onClick={() => resetDemoBaseline()}
          className="flex items-center space-x-1 px-2.5 py-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-cyan-500/50 text-slate-400 hover:text-cyan-300 transition-colors text-xs font-mono"
          title="Reset to Clean Baseline State"
        >
          <RotateCcw className="w-3.5 h-3.5 shrink-0" />
          <span className="hidden xl:inline">RESET</span>
        </button>

        {/* Interactive Notification Bell */}
        <div className="relative" ref={notifRef}>
          <button
            id="notif-bell-btn"
            onClick={() => {
              setIsNotifOpen(!isNotifOpen);
              setIsDropdownOpen(false);
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
              {/* Panel Header */}
              <div className="p-3.5 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
                <div className="flex items-center space-x-2">
                  <Bell className="w-4 h-4 text-cyan-400" />
                  <span className="text-xs font-bold uppercase tracking-wider">Notifications Center</span>
                  {unreadCount > 0 && (
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-rose-950 text-rose-400 border border-rose-800">
                      {unreadCount} unread
                    </span>
                  )}
                </div>

                <div className="flex items-center space-x-2 text-[11px] font-mono">
                  {unreadCount > 0 && (
                    <button
                      id="mark-all-read-btn"
                      onClick={markAllNotificationsRead}
                      className="text-cyan-400 hover:underline flex items-center space-x-1"
                      title="Mark all as read"
                    >
                      <Check className="w-3 h-3" />
                      <span>Read all</span>
                    </button>
                  )}
                  {notifications.length > 0 && (
                    <button
                      id="clear-notifs-btn"
                      onClick={clearNotifications}
                      className="text-slate-500 hover:text-rose-400 transition-colors"
                      title="Clear all notifications"
                    >
                      <Trash2 className="w-3 h-3" />
                    </button>
                  )}
                  <button
                    onClick={() => setIsNotifOpen(false)}
                    className="text-slate-500 hover:text-slate-300"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              {/* Notifications List */}
              <div className="max-h-96 overflow-y-auto divide-y divide-slate-800/80">
                {notifications.length === 0 ? (
                  <div className="p-8 text-center space-y-2">
                    <Bell className="w-8 h-8 text-slate-700 mx-auto" />
                    <p className="text-xs text-slate-500 font-mono">No active notifications.</p>
                  </div>
                ) : (
                  notifications.map((n) => (
                    <div
                      key={n.id}
                      id={`notif-${n.id}`}
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
                            <span>Go to {n.link}</span>
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

              {/* Footer */}
              {notifications.length > 0 && (
                <div className="p-2 border-t border-slate-800 bg-slate-950/40 text-center">
                  <span className="text-[10px] font-mono text-slate-600">{notifications.length} total notifications</span>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
