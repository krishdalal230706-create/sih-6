import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  ShieldAlert,
  Crosshair,
  GitBranch,
  Radio,
  AlertTriangle,
  Zap,
  EyeOff,
  Share2,
  Network,
  Database,
  Building2,
  FileText,
  Settings,
  ShieldCheck,
  TrendingUp,
  Laptop,
  ScrollText,
  LogOut,
  UserCheck,
  Landmark,
  X
} from 'lucide-react';
import { useApp } from '../../context/AppContext';
import { useAuth } from '../../context/AuthContext';

interface SidebarProps {
  isOpen?: boolean;
  onClose?: () => void;
}

interface NavItem {
  name: string;
  path: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
}

interface NavSection {
  heading: string;
  items: NavItem[];
}

export const Sidebar: React.FC<SidebarProps> = ({ isOpen = false, onClose }) => {
  const { activeOrg, riskData } = useApp();
  const { currentUser, logout } = useAuth();

  const enableEndpointAgent = (import.meta as any).env?.VITE_ENABLE_ENDPOINT_AGENT === 'true';

  // Grouped Navigation according to Phase 4 Console Structure
  const navSections: NavSection[] = [
    {
      heading: 'Monitor',
      items: [
        { name: 'Overview', path: '/', icon: LayoutDashboard },
        { name: 'Bank Assets', path: '/bank-assets', icon: Landmark, badge: 'BANK' },
        { name: 'Account Security', path: '/account-security', icon: UserCheck, badge: 'HERO' },
        ...(enableEndpointAgent ? [{ name: 'Endpoints', path: '/endpoints', icon: Laptop }] : []),
        { name: 'Incidents', path: '/incidents', icon: AlertTriangle }
      ]
    },
    {
      heading: 'Assess',
      items: [
        { name: 'Cyber Risk', path: '/cyber-risk', icon: ShieldAlert },
        { name: 'Attack Simulator', path: '/attack-simulator', icon: Crosshair },
        { name: 'Attack Path', path: '/attack-path', icon: GitBranch },
        { name: 'Threat Detection', path: '/threat-detection', icon: Radio }
      ]
    },
    {
      heading: 'Respond',
      items: [
        { name: 'Response Center', path: '/response-center', icon: Zap },
        { name: 'Investment Optimizer', path: '/investment-optimization', icon: TrendingUp }
      ]
    },
    {
      heading: 'Collaborate',
      items: [
        { name: 'Privacy Engine', path: '/privacy-engine', icon: EyeOff },
        { name: 'Threat Intelligence', path: '/threat-intelligence', icon: Share2 },
        { name: 'Collaborative Network', path: '/collaborative-network', icon: Network },
        { name: 'DLT Trust Ledger', path: '/dlt-ledger', icon: Database }
      ]
    },
    {
      heading: 'Govern',
      items: [
        { name: 'Audit Log', path: '/audit-log', icon: ScrollText, badge: 'CHAIN' },
        { name: 'Reports', path: '/reports', icon: FileText },
        { name: 'Organization', path: '/organizations', icon: Building2 },
        { name: 'Settings', path: '/settings', icon: Settings }
      ]
    }
  ];

  // Dynamic shared risk score adhering to unified severity bands: >=80 Critical, >=65 High, >=45 Medium, Low
  const currentRiskScore = riskData?.overallRiskScore ?? activeOrg?.riskScore ?? 42;
  const riskBadgeStyle = (() => {
    if (currentRiskScore >= 80) return 'bg-rose-950 text-rose-400 border-rose-800';
    if (currentRiskScore >= 65) return 'bg-orange-950 text-orange-400 border-orange-800';
    if (currentRiskScore >= 45) return 'bg-amber-950 text-amber-400 border-amber-800';
    return 'bg-emerald-950 text-emerald-400 border-emerald-800';
  })();

  const getOrgDisplayName = (orgId?: string) => {
    switch (orgId) {
      case 'org-1':
        return 'Demo Bank (India)';
      case 'org-2':
        return 'Hospital B';
      case 'org-3':
        return 'University C';
      default:
        return activeOrg?.name || 'Demo Bank (India)';
    }
  };

  return (
    <>
      {/* Mobile Backdrop Overlay */}
      {isOpen && (
        <div
          onClick={onClose}
          className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-40 lg:hidden transition-opacity"
          aria-hidden="true"
        />
      )}

      <aside
        className={`fixed lg:sticky top-0 left-0 z-50 lg:z-30 w-64 bg-[#0F1420] border-r border-slate-800/80 flex flex-col h-screen transition-transform duration-300 ease-in-out select-none ${
          isOpen ? 'translate-x-0 shadow-2xl' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        {/* Brand Header */}
        <div className="p-4 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 p-0.5 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <div className="w-full h-full bg-[#0B0F17] rounded-[10px] flex items-center justify-center">
                <ShieldCheck className="w-5 h-5 text-cyan-400" />
              </div>
            </div>
            <div>
              <h1 className="font-bold text-sm tracking-wider text-slate-100 uppercase">
                CYBERGUARD <span className="text-cyan-400">GRID</span>
              </h1>
              <p className="text-[9px] text-cyan-400/90 font-mono tracking-wide">BANKING SECURITY EDITION</p>
            </div>
          </div>

          {/* Close button for mobile */}
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 lg:hidden"
            title="Close menu"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Static Assigned Organization Scope Badge */}
        <div className="px-3 py-2 mx-3 my-2.5 bg-slate-900/90 border border-slate-800 rounded-lg">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2 truncate">
              <Building2 className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
              <span className="text-xs font-semibold text-slate-200 truncate">
                {getOrgDisplayName(currentUser?.orgId)}
              </span>
            </div>
            <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-bold border ${riskBadgeStyle}`}>
              {currentRiskScore} RS
            </span>
          </div>
          <div className="text-[10px] font-mono text-slate-500 mt-0.5 truncate">
            {activeOrg?.type || 'Enterprise Node'} • Scoped
          </div>
        </div>

        {/* Grouped Navigation Menu */}
        <nav className="flex-1 px-3 py-1 space-y-4 overflow-y-auto">
          {navSections.map((section) => (
            <div key={section.heading} className="space-y-1">
              <div className="px-3 py-1 text-[10px] font-mono font-bold text-slate-500 uppercase tracking-wider">
                {section.heading}
              </div>

              {section.items.map((item) => {
                const Icon = item.icon;
                return (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    onClick={onClose}
                    className={({ isActive }) =>
                      `flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-all duration-200 ${
                        isActive
                          ? 'bg-gradient-to-r from-cyan-500/15 to-blue-500/5 text-cyan-400 border-l-2 border-cyan-400 shadow-sm'
                          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                      }`
                    }
                  >
                    <div className="flex items-center space-x-2.5">
                      <Icon className="w-4 h-4 shrink-0" />
                      <span>{item.name}</span>
                    </div>
                    {item.badge && (
                      <span className="text-[9px] px-1.5 py-0.2 rounded font-mono bg-cyan-950 text-cyan-400 border border-cyan-800/60 font-semibold">
                        {item.badge}
                      </span>
                    )}
                  </NavLink>
                );
              })}
            </div>
          ))}
        </nav>

        {/* User Profile & Role Status */}
        <div className="px-3 py-2 border-t border-slate-800/80 bg-slate-900/40">
          <div className="flex items-center justify-between p-2 rounded-lg bg-[#0B0F17] border border-slate-800/80">
            <div className="flex items-center space-x-2 min-w-0">
              <div className="w-6 h-6 rounded-full bg-cyan-950 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shrink-0 text-xs font-bold">
                {currentUser?.name?.[0] || 'A'}
              </div>
              <div className="min-w-0">
                <div className="text-xs font-semibold text-slate-200 truncate">
                  {currentUser?.name || 'Administrator'}
                </div>
                <div className="text-[10px] text-slate-500 font-mono truncate">{currentUser?.email}</div>
              </div>
            </div>
            <button
              type="button"
              onClick={logout}
              title="Sign Out"
              className="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-rose-950/30 rounded transition-colors shrink-0"
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Footer System Status */}
        <div className="p-3 border-t border-slate-800/80 bg-slate-950/40 text-[10px] font-mono text-slate-500 flex items-center justify-between">
          <div className="flex items-center space-x-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>GRID CONSENSUS OK</span>
          </div>
          <span>RBAC ENFORCED</span>
        </div>
      </aside>
    </>
  );
};
