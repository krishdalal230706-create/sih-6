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
  Bell,
  TrendingUp,
  X
} from 'lucide-react';
import { useApp } from '../../context/AppContext';

interface SidebarProps {
  isOpen?: boolean;
  onClose?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ isOpen = false, onClose }) => {
  const { activeOrg, unreadCount } = useApp();

  const navItems = [
    { name: 'Overview', path: '/', icon: LayoutDashboard },
    { name: 'Cyber Risk', path: '/cyber-risk', icon: ShieldAlert },
    { name: 'Attack Simulator', path: '/attack-simulator', icon: Crosshair },
    { name: 'Attack Path', path: '/attack-path', icon: GitBranch },
    { name: 'Threat Detection', path: '/threat-detection', icon: Radio },
    { name: 'Incidents', path: '/incidents', icon: AlertTriangle },
    { name: 'Response Center', path: '/response-center', icon: Zap },
    { name: 'Investment Optimizer', path: '/investment-optimization', icon: TrendingUp },
    { name: 'Privacy Engine', path: '/privacy-engine', icon: EyeOff },
    { name: 'Threat Intelligence', path: '/threat-intelligence', icon: Share2 },
    { name: 'Collaborative Network', path: '/collaborative-network', icon: Network },
    { name: 'DLT Trust Ledger', path: '/dlt-ledger', icon: Database },
    { name: 'Organizations', path: '/organizations', icon: Building2 },
    { name: 'Reports', path: '/reports', icon: FileText },
    { name: 'Settings', path: '/settings', icon: Settings }
  ];

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
        className={`fixed lg:sticky top-0 left-0 z-50 lg:z-30 w-64 bg-[#0F1420] border-r border-slate-800/80 flex flex-col h-screen transition-transform duration-300 ease-in-out select-none ${isOpen ? 'translate-x-0 shadow-2xl' : '-translate-x-full lg:translate-x-0'
          }`}
      >
        {/* Brand Header */}
        <div className="p-5 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 p-0.5 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <div className="w-full h-full bg-[#0B0F17] rounded-[10px] flex items-center justify-center">
                <ShieldCheck className="w-6 h-6 text-cyan-400" />
              </div>
            </div>
            <div>
              <h1 className="font-bold text-base tracking-wider text-slate-100 uppercase">
                CYBERGUARD <span className="text-cyan-400">GRID</span>
              </h1>
              <p className="text-[10px] text-slate-400 font-mono tracking-wide">SOC COMMAND CENTER</p>
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

        {/* Organization Badge */}
        <div className="px-4 py-3 mx-3 my-3 bg-slate-900/80 border border-slate-800 rounded-lg">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2 truncate">
              <Building2 className="w-4 h-4 text-cyan-400 shrink-0" />
              <span className="text-xs font-semibold text-slate-200 truncate">
                {activeOrg ? activeOrg.name : 'Demo Bank'}
              </span>
            </div>
            <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-bold border ${(activeOrg?.riskScore ?? 84) >= 80
                ? 'bg-rose-950 text-rose-400 border-rose-800'
                : (activeOrg?.riskScore ?? 84) >= 65
                  ? 'bg-amber-950 text-amber-400 border-amber-800'
                  : 'bg-emerald-950 text-emerald-400 border-emerald-800'
              }`}>
              {activeOrg ? `${activeOrg.riskScore} RS` : '84 RS'}
            </span>
          </div>
          <div className="text-[10px] font-mono text-slate-500 mt-1 truncate">{activeOrg?.type}</div>
        </div>

        {/* Navigation Menu */}
        <nav className="flex-1 px-3 py-2 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                onClick={onClose}
                className={({ isActive }) =>
                  `flex items-center space-x-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-all duration-200 ${isActive
                    ? 'bg-gradient-to-r from-cyan-500/15 to-blue-500/5 text-cyan-400 border-l-2 border-cyan-400 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                  }`
                }
              >
                <Icon className="w-4 h-4 shrink-0" />
                <span>{item.name}</span>
              </NavLink>
            );
          })}
        </nav>

        {/* Footer System Status */}
        <div className="p-4 border-t border-slate-800/80 bg-slate-950/40 text-[11px] font-mono text-slate-500 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>LEDGER ENGINE OK</span>
          </div>
          <span>v1.0-PROTO</span>
        </div>
      </aside>
    </>
  );
};
