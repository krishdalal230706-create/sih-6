import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Share2,
  CheckCircle2,
  ArrowRight,
  ShieldCheck,
  Search,
  Filter,
  Copy,
  Layers,
  Building2,
  AlertTriangle,
  Radio,
  ExternalLink,
  X,
  Sparkles,
  Cpu,
  Globe,
  Clock,
  Check,
  RefreshCw,
  Flame,
  ShieldAlert,
  Info,
  Sliders,
  ChevronLeft,
  ChevronRight,
  Database,
  Calendar,
  Tag,
  Shield,
  Zap,
  Activity
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import { VulnerabilityRecord, VulnerabilityFilterOptions } from '../types';

export const ThreatIntelligence: React.FC = () => {
  const {
    threatPatterns,
    organizations,
    addNotification,
    broadcastPatternToMesh,
    vulnerabilities,
    vulnerabilityStats,
    syncStatus,
    vulnPagination,
    isLoadingVulns,
    isSyncingVulns,
    fetchVulnerabilities,
    triggerLiveSync
  } = useApp();

  const navigate = useNavigate();

  // Active view tab: 'VULNERABILITIES' | 'BEHAVIORAL_PATTERNS'
  const [activeTab, setActiveTab] = useState<'VULNERABILITIES' | 'BEHAVIORAL_PATTERNS'>('VULNERABILITIES');

  // Filter & Search State
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [selectedPriority, setSelectedPriority] = useState('ALL');
  const [selectedSource, setSelectedSource] = useState('ALL');
  const [knownExploitedOnly, setKnownExploitedOnly] = useState(false);
  const [sortBy, setSortBy] = useState<'cyberGuardScore' | 'cvssScore' | 'publishedDate' | 'modifiedDate'>('cyberGuardScore');
  const [sortOrder, setSortOrder] = useState<'desc' | 'asc'>('desc');
  const [currentPage, setCurrentPage] = useState(1);

  // Selected Vulnerability for Detail Modal
  const [selectedVuln, setSelectedVuln] = useState<VulnerabilityRecord | null>(null);

  // Behavioral Threat Pattern State
  const [selectedPatternCode, setSelectedPatternCode] = useState<string>('TH-7821');
  const [targetOrgId, setTargetOrgId] = useState<string>('org-2');
  const [comparisonResult, setComparisonResult] = useState<any>(null);
  const [isComparing, setIsComparing] = useState<boolean>(false);
  const [isBroadcasting, setIsBroadcasting] = useState<boolean>(false);
  const [broadcastResult, setBroadcastResult] = useState<any>(null);
  const [showBroadcastModal, setShowBroadcastModal] = useState<boolean>(false);

  const selectedPattern = threatPatterns.find((p) => p.patternCode === selectedPatternCode) || threatPatterns[0];

  const { isDemoActive, demoStep } = useApp();

  // Automated Demo Scene Triggers for Screen Recording
  useEffect(() => {
    if (isDemoActive) {
      if (demoStep === 5) {
        if (vulnerabilities.length > 0) {
          setSelectedVuln(vulnerabilities[0]);
        }
      } else if (demoStep === 7) {
        setSelectedVuln(null);
        setKnownExploitedOnly(true);
        setSelectedSeverity('ALL');
      } else if (demoStep === 8) {
        setSelectedVuln(null);
        setKnownExploitedOnly(false);
        setSelectedSeverity('CRITICAL');
      } else if (demoStep !== 3 && demoStep !== 4) {
        setSelectedVuln(null);
        setKnownExploitedOnly(false);
        setSelectedSeverity('ALL');
      }
    }
  }, [isDemoActive, demoStep, vulnerabilities]);

  // Fetch vulnerabilities whenever filters or pagination change
  useEffect(() => {
    const filters: VulnerabilityFilterOptions = {
      search: searchQuery || undefined,
      severity: selectedSeverity !== 'ALL' ? selectedSeverity : undefined,
      cyberGuardPriority: selectedPriority !== 'ALL' ? selectedPriority : undefined,
      source: selectedSource !== 'ALL' ? selectedSource : undefined,
      knownExploited: knownExploitedOnly ? true : undefined,
      sortBy,
      sortOrder,
      page: currentPage,
      limit: 15
    };

    fetchVulnerabilities(filters);
  }, [searchQuery, selectedSeverity, selectedPriority, selectedSource, knownExploitedOnly, sortBy, sortOrder, currentPage]);

  const handleManualSync = async () => {
    await triggerLiveSync();
  };

  const handleComparePattern = async () => {
    setIsComparing(true);
    try {
      const res = await fetch('/api/threat-intelligence/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ threatCode: selectedPattern.patternCode, targetOrgId })
      }).then((r) => r.json());

      setComparisonResult(res.correlation);
    } catch (err) {
      console.error('Error comparing pattern:', err);
    } finally {
      setIsComparing(false);
    }
  };

  const handleSharePattern = async () => {
    setIsBroadcasting(true);
    try {
      const res = await broadcastPatternToMesh(selectedPattern.patternCode, targetOrgId);
      setBroadcastResult(res);
      setShowBroadcastModal(true);
    } catch (err) {
      console.error('Failed to broadcast pattern to mesh:', err);
    } finally {
      setIsBroadcasting(false);
    }
  };

  const formatTimeAgo = (isoString?: string | null) => {
    if (!isoString) return 'Just now';
    try {
      const diffMs = Date.now() - new Date(isoString).getTime();
      const diffMins = Math.floor(diffMs / (1000 * 60));
      if (diffMins < 1) return 'Just now';
      if (diffMins < 60) return `${diffMins} min ago`;
      const diffHours = Math.floor(diffMins / 60);
      if (diffHours < 24) return `${diffHours} hr ago`;
      return `${Math.floor(diffHours / 24)} days ago`;
    } catch {
      return 'Recently';
    }
  };

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 sm:space-y-8 max-w-7xl mx-auto">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex flex-wrap items-center gap-2 sm:gap-3">
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-100 uppercase">
              VULNERABILITY & THREAT INTELLIGENCE
            </h1>
            <span className="inline-flex items-center px-2.5 py-1 rounded-full text-[11px] font-mono font-bold bg-cyan-950 text-cyan-400 border border-cyan-800">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse mr-1.5"></span>
              LIVE INTELLIGENCE
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Authoritative vulnerability ingestion (NVD, CISA KEV, GitHub Advisories, OSV) paired with cryptographic DLT mesh threat patterns.
          </p>
        </div>

        {/* Sync Status & Trigger Controls */}
        <div className="flex items-center space-x-3 w-full sm:w-auto">
          <div className="px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 text-right flex-1 sm:flex-initial">
            <div className="text-[10px] font-mono text-slate-500 uppercase">Last Synchronized</div>
            <div className="text-xs font-mono font-bold text-slate-300">
              {formatTimeAgo(vulnerabilityStats?.lastSyncTime || syncStatus?.lastSyncTime)}
            </div>
          </div>

          <button
            onClick={handleManualSync}
            disabled={isSyncingVulns}
            className={`px-3.5 sm:px-4 py-2 rounded-xl text-xs font-mono font-bold flex items-center justify-center space-x-2 transition-all flex-1 sm:flex-initial ${
              isSyncingVulns
                ? 'bg-cyan-950 border border-cyan-500 text-cyan-300 cursor-wait'
                : 'bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 shadow-lg glow-cyan'
            }`}
          >
            <RefreshCw className={`w-3.5 h-3.5 shrink-0 ${isSyncingVulns ? 'animate-spin' : ''}`} />
            <span className="truncate">{isSyncingVulns ? 'SYNCHRONIZING...' : 'SYNC INTELLIGENCE'}</span>
          </button>
        </div>
      </div>

      {/* Navigation Tab Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 sm:space-x-2 border-b border-slate-800 pb-1">
        <button
          onClick={() => setActiveTab('VULNERABILITIES')}
          className={`px-3.5 sm:px-5 py-2.5 rounded-t-xl text-[11px] sm:text-xs font-bold font-mono tracking-wider flex items-center justify-center space-x-2 transition-all ${
            activeTab === 'VULNERABILITIES'
              ? 'bg-slate-900 text-cyan-400 border-t-2 border-x border-slate-800 border-t-cyan-400 shadow-md'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
          }`}
        >
          <Database className="w-4 h-4 shrink-0" />
          <span className="truncate">LIVE VULNERABILITY INTELLIGENCE ({vulnerabilityStats?.total || vulnerabilities.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('BEHAVIORAL_PATTERNS')}
          className={`px-3.5 sm:px-5 py-2.5 rounded-t-xl text-[11px] sm:text-xs font-bold font-mono tracking-wider flex items-center justify-center space-x-2 transition-all ${
            activeTab === 'BEHAVIORAL_PATTERNS'
              ? 'bg-slate-900 text-cyan-400 border-t-2 border-x border-slate-800 border-t-cyan-400 shadow-md'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
          }`}
        >
          <Share2 className="w-4 h-4 shrink-0" />
          <span className="truncate">SHARED BEHAVIORAL PATTERNS ({threatPatterns.length})</span>
        </button>
      </div>

      {/* TAB 1: LIVE VULNERABILITY INTELLIGENCE */}
      {activeTab === 'VULNERABILITIES' && (
        <div className="space-y-6">
          {/* 4 Summary Stat Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Total Vulnerabilities */}
            <div className="glass-panel p-4 rounded-2xl border border-slate-800 bg-slate-900/70 relative overflow-hidden">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono text-slate-400 uppercase">TOTAL INTELLIGENCE</span>
                <Database className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="text-3xl font-black font-mono text-slate-100 mt-2">
                {vulnerabilityStats?.total || vulnerabilities.length}
              </div>
              <div className="text-[10px] font-mono text-slate-500 mt-1 flex items-center space-x-1">
                <span>NVD • CISA KEV • OSV • GitHub</span>
              </div>
            </div>

            {/* Critical Severity */}
            <div className="glass-panel p-4 rounded-2xl border border-rose-900/40 bg-rose-950/20 relative overflow-hidden">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono text-rose-300 uppercase">CRITICAL SEVERITY</span>
                <ShieldAlert className="w-4 h-4 text-rose-400" />
              </div>
              <div className="text-3xl font-black font-mono text-rose-400 mt-2">
                {vulnerabilityStats?.critical || 0}
              </div>
              <div className="text-[10px] font-mono text-rose-300/70 mt-1">
                CVSS 9.0+ or high blast radius
              </div>
            </div>

            {/* Known Exploited in Wild (CISA KEV) */}
            <div className="glass-panel p-4 rounded-2xl border border-amber-900/40 bg-amber-950/20 relative overflow-hidden">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono text-amber-300 uppercase">CISA KEV EXPLOITED</span>
                <Flame className="w-4 h-4 text-amber-400 animate-pulse" />
              </div>
              <div className="text-3xl font-black font-mono text-amber-400 mt-2">
                {vulnerabilityStats?.knownExploited || 0}
              </div>
              <div className="text-[10px] font-mono text-amber-300/70 mt-1">
                Active Weaponization in Wild
              </div>
            </div>

            {/* CyberGuard Priority Metric */}
            <div className="glass-panel p-4 rounded-2xl border border-cyan-900/40 bg-cyan-950/20 relative overflow-hidden">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono text-cyan-300 uppercase">AVG CYBERGUARD RISK</span>
                <Sparkles className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="text-3xl font-black font-mono text-cyan-400 mt-2">
                {vulnerabilityStats?.avgCyberGuardScore || 96.5}
                <span className="text-xs font-normal text-slate-500 font-mono ml-1">/ 100</span>
              </div>
              <div className="text-[10px] font-mono text-cyan-300/70 mt-1">
                Avg CVSS: {vulnerabilityStats?.avgCvssScore || 9.2} / 10
              </div>
            </div>
          </div>

          {/* Search, Filter & Toolbar Bar */}
          <div className="glass-panel p-4 rounded-2xl border border-slate-800 bg-slate-900/60 space-y-3">
            <div className="flex flex-col md:flex-row items-stretch md:items-center gap-3">
              {/* Search input */}
              <div className="relative flex-1">
                <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Search by CVE ID, Vendor, Product, or keyword (e.g. PAN-OS, ScreenConnect, RCE)..."
                  value={searchQuery}
                  onChange={(e) => {
                    setSearchQuery(e.target.value);
                    setCurrentPage(1);
                  }}
                  className="w-full pl-10 pr-4 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
                />
              </div>

              {/* Known Exploited toggle button */}
              <button
                onClick={() => {
                  setKnownExploitedOnly(!knownExploitedOnly);
                  setCurrentPage(1);
                }}
                className={`px-3 py-2 rounded-xl border text-xs font-mono font-bold flex items-center space-x-1.5 transition-all ${
                  knownExploitedOnly
                    ? 'bg-amber-950 text-amber-300 border-amber-500 shadow-md shadow-amber-950/50'
                    : 'bg-slate-950 hover:bg-slate-900 text-slate-400 border-slate-800'
                }`}
              >
                <Flame className={`w-3.5 h-3.5 ${knownExploitedOnly ? 'text-amber-400 animate-pulse' : 'text-slate-500'}`} />
                <span>CISA KEV Only</span>
              </button>
            </div>

            {/* Filter Dropdowns Row */}
            <div className="flex flex-wrap items-center gap-3 text-xs font-mono pt-2 border-t border-slate-800/80">
              <div className="flex items-center space-x-1.5">
                <span className="text-slate-500">Severity:</span>
                <select
                  value={selectedSeverity}
                  onChange={(e) => {
                    setSelectedSeverity(e.target.value);
                    setCurrentPage(1);
                  }}
                  className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 focus:outline-none focus:border-cyan-500"
                >
                  <option value="ALL">All Severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>

              <div className="flex items-center space-x-1.5">
                <span className="text-slate-500">Priority:</span>
                <select
                  value={selectedPriority}
                  onChange={(e) => {
                    setSelectedPriority(e.target.value);
                    setCurrentPage(1);
                  }}
                  className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 focus:outline-none focus:border-cyan-500"
                >
                  <option value="ALL">All Priority Tiers</option>
                  <option value="CRITICAL">Critical Priority</option>
                  <option value="HIGH">High Priority</option>
                  <option value="MEDIUM">Medium Priority</option>
                  <option value="LOW">Low Priority</option>
                </select>
              </div>

              <div className="flex items-center space-x-1.5">
                <span className="text-slate-500">Source:</span>
                <select
                  value={selectedSource}
                  onChange={(e) => {
                    setSelectedSource(e.target.value);
                    setCurrentPage(1);
                  }}
                  className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 focus:outline-none focus:border-cyan-500"
                >
                  <option value="ALL">All Authoritative Feeds</option>
                  <option value="CISA KEV">CISA KEV</option>
                  <option value="NVD">NVD 2.0</option>
                  <option value="OSV">OSV.dev</option>
                  <option value="GitHub Advisory">GitHub Advisory</option>
                </select>
              </div>

              <div className="flex items-center space-x-1.5 ml-auto">
                <span className="text-slate-500">Sort:</span>
                <select
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value as any)}
                  className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 focus:outline-none focus:border-cyan-500"
                >
                  <option value="cyberGuardScore">CyberGuard Priority Score</option>
                  <option value="cvssScore">CVSS Score</option>
                  <option value="publishedDate">Publication Date</option>
                  <option value="modifiedDate">Last Modified Date</option>
                </select>
              </div>
            </div>
          </div>

          {/* Vulnerability Table & List */}
          <div className="glass-panel rounded-2xl border border-slate-800 overflow-hidden bg-slate-900/60">
            {isLoadingVulns ? (
              <div className="p-12 flex items-center justify-center text-slate-400 font-mono space-x-3">
                <Activity className="w-5 h-5 animate-spin text-cyan-400" />
                <span>Querying local persistent vulnerability intelligence database...</span>
              </div>
            ) : vulnerabilities.length === 0 ? (
              <div className="p-12 text-center font-mono space-y-3">
                <Info className="w-8 h-8 text-slate-500 mx-auto" />
                <p className="text-slate-300 font-bold">No vulnerabilities matched your search criteria.</p>
                <p className="text-xs text-slate-500">Try clearing your filters or triggering a live synchronization.</p>
                <button
                  onClick={() => {
                    setSearchQuery('');
                    setSelectedSeverity('ALL');
                    setSelectedPriority('ALL');
                    setSelectedSource('ALL');
                    setKnownExploitedOnly(false);
                  }}
                  className="px-4 py-2 rounded-xl bg-slate-800 text-cyan-400 text-xs font-mono font-bold hover:bg-slate-700"
                >
                  Reset All Filters
                </button>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono border-collapse">
                  <thead>
                    <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase text-[11px] tracking-wider">
                      <th className="py-3.5 px-4 font-bold">CVE Identifier</th>
                      <th className="py-3.5 px-4 font-bold">CyberGuard Priority</th>
                      <th className="py-3.5 px-4 font-bold">CVSS</th>
                      <th className="py-3.5 px-4 font-bold">Affected Asset</th>
                      <th className="py-3.5 px-4 font-bold">Weaponization</th>
                      <th className="py-3.5 px-4 font-bold">Authoritative Source</th>
                      <th className="py-3.5 px-4 font-bold text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {vulnerabilities.map((vuln) => {
                      const isCriticalPriority = vuln.cyberGuardPriority === 'CRITICAL';
                      const isHighPriority = vuln.cyberGuardPriority === 'HIGH';

                      return (
                        <tr
                          key={vuln.id}
                          onClick={() => setSelectedVuln(vuln)}
                          className="hover:bg-slate-800/40 cursor-pointer transition-colors group"
                        >
                          {/* CVE ID */}
                          <td className="py-3.5 px-4">
                            <div className="font-bold text-slate-100 group-hover:text-cyan-400 transition-colors flex items-center space-x-1.5">
                              <span>{vuln.cveId}</span>
                            </div>
                            <div className="text-[11px] text-slate-400 truncate max-w-xs mt-0.5">
                              {vuln.title || vuln.description.slice(0, 50)}
                            </div>
                          </td>

                          {/* CyberGuard Priority */}
                          <td className="py-3.5 px-4">
                            <div className="flex items-center space-x-2">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                                  isCriticalPriority
                                    ? 'bg-rose-950 text-rose-400 border-rose-800 shadow-sm shadow-rose-950'
                                    : isHighPriority
                                    ? 'bg-amber-950 text-amber-400 border-amber-800'
                                    : 'bg-blue-950 text-blue-400 border-blue-800'
                                }`}
                              >
                                {vuln.cyberGuardPriority}
                              </span>
                              <span className="font-black text-cyan-400 text-xs">
                                {vuln.cyberGuardScore}/100
                              </span>
                            </div>
                          </td>

                          {/* CVSS Score */}
                          <td className="py-3.5 px-4">
                            <span
                              className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                                vuln.cvssScore >= 9.0
                                  ? 'bg-rose-950/80 text-rose-300 border border-rose-800/80'
                                  : vuln.cvssScore >= 7.0
                                  ? 'bg-amber-950/80 text-amber-300 border border-amber-800/80'
                                  : 'bg-slate-900 text-slate-300 border border-slate-700'
                              }`}
                            >
                              {vuln.cvssScore.toFixed(1)}
                            </span>
                          </td>

                          {/* Affected Vendor & Product */}
                          <td className="py-3.5 px-4">
                            <div className="text-slate-200 font-semibold truncate max-w-xs">
                              {vuln.affectedProduct || 'System Component'}
                            </div>
                            <div className="text-[10px] text-slate-500 truncate max-w-xs">
                              {vuln.affectedVendor}
                            </div>
                          </td>

                          {/* Known Exploited / Weaponization */}
                          <td className="py-3.5 px-4">
                            {vuln.knownExploited ? (
                              <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-800 animate-pulse">
                                <Flame className="w-3 h-3 mr-1 text-amber-400" />
                                CISA KEV
                              </span>
                            ) : vuln.exploitAvailable ? (
                              <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950/60 text-rose-300 border border-rose-900">
                                PoC Available
                              </span>
                            ) : (
                              <span className="text-[10px] text-slate-500">Unconfirmed</span>
                            )}
                          </td>

                          {/* Authoritative Source */}
                          <td className="py-3.5 px-4">
                            <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-[10px] text-cyan-400 font-bold">
                              {vuln.source}
                            </span>
                          </td>

                          {/* Inspect Action */}
                          <td className="py-3.5 px-4 text-right">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedVuln(vuln);
                              }}
                              className="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-cyan-950 hover:text-cyan-300 hover:border-cyan-700 border border-slate-800 text-[11px] text-slate-300 transition-colors"
                            >
                              Inspect
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}

            {/* Pagination Controls */}
            {vulnPagination.totalPages > 1 && (
              <div className="p-4 border-t border-slate-800 flex items-center justify-between text-xs font-mono text-slate-400 bg-slate-950/60">
                <div>
                  Showing Page <strong className="text-slate-200">{vulnPagination.page}</strong> of{' '}
                  <strong className="text-slate-200">{vulnPagination.totalPages}</strong> ({vulnPagination.total} total records)
                </div>

                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                    disabled={vulnPagination.page <= 1}
                    className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-200"
                  >
                    <ChevronLeft className="w-4 h-4" />
                  </button>

                  <span className="px-3 py-1 rounded bg-slate-900 border border-slate-800 text-cyan-400 font-bold">
                    {vulnPagination.page}
                  </span>

                  <button
                    onClick={() => setCurrentPage((p) => Math.min(vulnPagination.totalPages, p + 1))}
                    disabled={vulnPagination.page >= vulnPagination.totalPages}
                    className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-200"
                  >
                    <ChevronRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: SHARED BEHAVIORAL PATTERNS (DLT Mesh) */}
      {activeTab === 'BEHAVIORAL_PATTERNS' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Pattern Cards List */}
          <div className="lg:col-span-2 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">
                DECENTRALIZED THREAT BEHAVIOR CARDS
              </h3>
              <span className="text-xs font-mono text-slate-400">Click to inspect & correlate</span>
            </div>

            <div className="space-y-4">
              {threatPatterns.map((tp) => {
                const isSelected = selectedPatternCode === tp.patternCode;
                return (
                  <div
                    key={tp.id}
                    onClick={() => {
                      setSelectedPatternCode(tp.patternCode);
                      setComparisonResult(null);
                    }}
                    className={`p-5 rounded-2xl border cursor-pointer transition-all ${
                      isSelected
                        ? 'glass-panel border-cyan-500/80 shadow-lg shadow-cyan-950/50'
                        : 'bg-slate-900/80 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <span className="font-mono text-base font-black text-cyan-400">{tp.patternCode}</span>
                        <span
                          className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                            tp.severity === 'CRITICAL'
                              ? 'bg-rose-950 text-rose-400 border-rose-800'
                              : 'bg-amber-950 text-amber-400 border-amber-800'
                          }`}
                        >
                          {tp.severity}
                        </span>
                      </div>

                      <div className="flex items-center space-x-2 text-xs font-mono">
                        <span className="text-slate-400">Origin: <strong>{tp.originOrgName}</strong></span>
                        <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                          ✓ {tp.status}
                        </span>
                      </div>
                    </div>

                    <div className="my-3 flex flex-wrap items-center gap-2 text-xs font-mono">
                      {tp.patternSequence.map((evt, idx) => (
                        <React.Fragment key={idx}>
                          <span className="px-2.5 py-1 rounded bg-slate-950 border border-slate-800 text-slate-300">
                            {evt}
                          </span>
                          {idx < tp.patternSequence.length - 1 && <ArrowRight className="w-3.5 h-3.5 text-cyan-400" />}
                        </React.Fragment>
                      ))}
                    </div>

                    <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 pt-2 border-t border-slate-800/80">
                      <span>Hash: {tp.hash.slice(0, 16)}...{tp.hash.slice(-8)}</span>
                      <span className="text-cyan-400">Confidence: {tp.confidence}%</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Selected Pattern Comparison Drawer */}
          <div className="glass-panel p-6 rounded-2xl border border-cyan-500/30 space-y-6">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
                <Share2 className="w-4 h-4 text-cyan-400" />
                <span>PATTERN CORRELATION TOOL</span>
              </h3>
            </div>

            <div>
              <div className="text-[10px] font-mono text-slate-500 uppercase">Selected Threat Pattern</div>
              <div className="text-xl font-bold font-mono text-cyan-400 mt-0.5">{selectedPattern.patternCode}</div>
              <p className="text-xs text-slate-400 mt-1">Origin: {selectedPattern.originOrgName}</p>
            </div>

            <div className="space-y-2 text-xs">
              <label className="block font-mono text-slate-400">Select Target Peer Organization</label>
              <select
                value={targetOrgId}
                onChange={(e) => setTargetOrgId(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
              >
                {organizations.map((org) => (
                  <option key={org.id} value={org.id}>
                    {org.name} ({org.type})
                  </option>
                ))}
              </select>
            </div>

            <div className="space-y-2.5">
              <button
                onClick={handleComparePattern}
                disabled={isComparing}
                className="w-full py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs shadow-lg glow-cyan transition-all"
              >
                {isComparing ? 'CORRELATING PATTERNS...' : 'COMPARE WITH TARGET TELEMETRY'}
              </button>

              <button
                onClick={handleSharePattern}
                disabled={isBroadcasting}
                className={`w-full py-2.5 rounded-xl border text-xs font-mono font-bold flex items-center justify-center space-x-2 transition-all ${
                  isBroadcasting
                    ? 'bg-cyan-950/70 border-cyan-500 text-cyan-300 animate-pulse cursor-wait'
                    : 'bg-slate-900 hover:bg-slate-800 border-slate-700 hover:border-cyan-500 text-slate-200 hover:text-white shadow-md'
                }`}
              >
                <Radio className={`w-3.5 h-3.5 text-cyan-400 ${isBroadcasting ? 'animate-spin' : ''}`} />
                <span>{isBroadcasting ? 'BROADCASTING TO MESH...' : 'Broadcast Pattern to Network Mesh'}</span>
              </button>
            </div>

            {/* Broadcast Confirmation Mini Card */}
            {broadcastResult && (
              <div className="p-3.5 rounded-xl bg-cyan-950/40 border border-cyan-500/50 space-y-2 font-mono text-xs animate-fadeIn">
                <div className="flex items-center justify-between">
                  <span className="flex items-center space-x-1.5 text-emerald-400 font-bold text-[11px]">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>MESH BROADCAST CONFIRMED</span>
                  </span>
                  <span className="text-[10px] text-cyan-400 font-mono">Block #{broadcastResult.ledgerBlock?.blockNumber || 10421}</span>
                </div>
                <p className="text-[11px] text-slate-300">
                  Propagated across {broadcastResult.meshPropagation?.length || 4} connected peer organizations.
                </p>
                <button
                  onClick={() => setShowBroadcastModal(true)}
                  className="text-cyan-400 hover:text-cyan-300 underline text-[11px] flex items-center space-x-1 pt-1"
                >
                  <span>View Peer Propagation Details</span>
                  <ArrowRight className="w-3 h-3" />
                </button>
              </div>
            )}

            {comparisonResult && (
              <div className="p-4 rounded-xl bg-cyan-950/40 border border-cyan-800/80 space-y-4 font-mono text-xs animate-fadeIn">
                {/* Early Warning Banner */}
                {comparisonResult.earlyWarningTriggered ? (
                  <div className="p-3 rounded-lg bg-rose-950/80 border border-rose-800 text-rose-300 flex items-start space-x-2 animate-pulse">
                    <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                    <div className="space-y-0.5">
                      <div className="font-bold text-[11px] uppercase tracking-wider text-rose-200">
                        EARLY WARNING TRIGGERED ({comparisonResult.similarityPercentage}% Sequence Match)
                      </div>
                      <p className="text-[10px] text-rose-300/90 leading-tight">
                        Adversary behavior sequence closely matches active intrusion pattern in {comparisonResult.targetOrgName}.
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="p-2.5 rounded-lg bg-emerald-950/60 border border-emerald-800 text-emerald-300 flex items-center space-x-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    <div className="text-[10px]">
                      Sequence match ({comparisonResult.similarityPercentage}%) below early warning threshold. Normal posture.
                    </div>
                  </div>
                )}

                <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                  <span className="text-slate-400">Target Peer:</span>
                  <span className="font-bold text-slate-100">{comparisonResult.targetOrgName}</span>
                </div>

                <div className="space-y-1">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-slate-400">LCS Ordered Similarity:</span>
                    <span className={`font-black text-sm ${comparisonResult.similarityPercentage >= 65 ? 'text-rose-400' : 'text-cyan-400'}`}>
                      {comparisonResult.similarityPercentage}%
                    </span>
                  </div>
                  <div className="w-full bg-slate-900 rounded-full h-1.5 overflow-hidden border border-slate-800">
                    <div
                      className={`h-full rounded-full transition-all duration-500 ${
                        comparisonResult.similarityPercentage >= 65 ? 'bg-rose-500' : 'bg-cyan-500'
                      }`}
                      style={{ width: `${comparisonResult.similarityPercentage}%` }}
                    />
                  </div>
                </div>

                {/* Side-by-Side Aligned Sequence Comparison */}
                {comparisonResult.sequenceComparison && (
                  <div className="space-y-2 pt-2 border-t border-slate-800">
                    <div className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">
                      Side-by-Side Sequence Alignment
                    </div>

                    <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
                      {comparisonResult.sequenceComparison.alignedBreakdown?.map((item: any, i: number) => {
                        const isMatched = item.status === 'MATCHED';
                        const isMissing = item.status === 'MISSING_IN_TARGET';

                        return (
                          <div
                            key={i}
                            className={`p-2 rounded-lg border text-[11px] font-mono flex items-center justify-between ${
                              isMatched
                                ? 'bg-emerald-950/40 border-emerald-800 text-emerald-200'
                                : isMissing
                                ? 'bg-amber-950/30 border-amber-800/80 text-amber-300'
                                : 'bg-slate-900 border-slate-800 text-slate-300'
                            }`}
                          >
                            <div className="flex items-center space-x-1.5 truncate max-w-[65%]">
                              <span className="text-slate-500 text-[9px] shrink-0">#{i + 1}</span>
                              <span className="truncate font-semibold">{item.eventA || item.eventB}</span>
                            </div>

                            <span
                              className={`px-1.5 py-0.5 rounded text-[9px] font-bold border shrink-0 ${
                                isMatched
                                  ? 'bg-emerald-950 text-emerald-300 border-emerald-700'
                                  : isMissing
                                  ? 'bg-amber-950 text-amber-300 border-amber-700'
                                  : 'bg-slate-800 text-slate-400 border-slate-700'
                              }`}
                            >
                              {isMatched ? '✓ MATCHED' : isMissing ? '⚠️ MISSING IN TARGET' : '+ EXTRA'}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* DETAILED VULNERABILITY INSPECTOR MODAL */}
      {selectedVuln && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md animate-fadeIn">
          <div className="glass-panel w-full max-w-3xl max-h-[90vh] overflow-y-auto rounded-2xl border border-cyan-500/50 shadow-2xl shadow-cyan-950/80 p-6 space-y-5">
            {/* Modal Header */}
            <div className="flex items-start justify-between border-b border-slate-800 pb-4">
              <div className="space-y-1">
                <div className="flex items-center space-x-3">
                  <span className="font-mono text-xl font-black text-cyan-400">{selectedVuln.cveId}</span>
                  <span
                    className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold border ${
                      selectedVuln.cyberGuardPriority === 'CRITICAL'
                        ? 'bg-rose-950 text-rose-400 border-rose-800'
                        : selectedVuln.cyberGuardPriority === 'HIGH'
                        ? 'bg-amber-950 text-amber-400 border-amber-800'
                        : 'bg-blue-950 text-blue-400 border-blue-800'
                    }`}
                  >
                    CYBERGUARD: {selectedVuln.cyberGuardPriority}
                  </span>
                  {selectedVuln.knownExploited && (
                    <span className="px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-amber-950 text-amber-300 border border-amber-800 flex items-center space-x-1 animate-pulse">
                      <Flame className="w-3.5 h-3.5 text-amber-400" />
                      <span>CISA KEV EXPLOITED</span>
                    </span>
                  )}
                </div>
                <h3 className="text-sm font-semibold text-slate-200 mt-1">{selectedVuln.title}</h3>
              </div>

              <button
                onClick={() => setSelectedVuln(null)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Risk & CVSS Metrics Row */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
              <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                <div className="text-[10px] text-slate-500 uppercase">CyberGuard Score</div>
                <div className="text-lg font-black text-cyan-400 mt-1">{selectedVuln.cyberGuardScore} / 100</div>
              </div>
              <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                <div className="text-[10px] text-slate-500 uppercase">Original CVSS Score</div>
                <div className="text-lg font-black text-rose-400 mt-1">{selectedVuln.cvssScore.toFixed(1)} / 10.0</div>
              </div>
              <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                <div className="text-[10px] text-slate-500 uppercase">Attack Vector</div>
                <div className="text-xs font-bold text-slate-200 mt-1.5">{selectedVuln.attackVector || 'NETWORK'}</div>
              </div>
              <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                <div className="text-[10px] text-slate-500 uppercase">Confidence Rating</div>
                <div className="text-xs font-bold text-emerald-400 mt-1.5">{selectedVuln.confidence}% Verified</div>
              </div>
            </div>

            {/* Description */}
            <div className="space-y-1.5">
              <div className="text-xs font-mono font-bold text-slate-400 uppercase">Vulnerability Intelligence Analysis</div>
              <p className="text-xs text-slate-300 leading-relaxed p-3.5 rounded-xl bg-slate-950/80 border border-slate-800/80">
                {selectedVuln.description}
              </p>
            </div>

            {/* Affected Asset & Vendor Info */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                <div className="text-[10px] text-slate-500 uppercase">Affected Vendor & Product</div>
                <div className="text-slate-200 font-bold">{selectedVuln.affectedProduct}</div>
                <div className="text-slate-400 text-[11px]">Vendor: {selectedVuln.affectedVendor}</div>
                {selectedVuln.affectedVersions && (
                  <div className="text-cyan-400 text-[10px]">Versions: {selectedVuln.affectedVersions}</div>
                )}
              </div>

              <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                <div className="text-[10px] text-slate-500 uppercase">Source & Timeline</div>
                <div className="text-slate-200 font-bold">Source: {selectedVuln.source}</div>
                <div className="text-slate-400 text-[11px]">Published: {selectedVuln.publishedDate.slice(0, 10)}</div>
                <div className="text-slate-400 text-[11px]">Last Modified: {selectedVuln.modifiedDate.slice(0, 10)}</div>
              </div>
            </div>

            {/* Remediation Guidance */}
            {selectedVuln.remediation && (
              <div className="space-y-1.5">
                <div className="text-xs font-mono font-bold text-emerald-400 uppercase flex items-center space-x-1.5">
                  <ShieldCheck className="w-4 h-4" />
                  <span>Authoritative Remediation & Mitigation Directive</span>
                </div>
                <div className="p-3.5 rounded-xl bg-emerald-950/30 border border-emerald-800/60 text-xs text-emerald-200 font-mono leading-relaxed">
                  {selectedVuln.remediation}
                </div>
              </div>
            )}

            {/* References */}
            {selectedVuln.references && selectedVuln.references.length > 0 && (
              <div className="space-y-1.5">
                <div className="text-xs font-mono font-bold text-slate-400 uppercase">Authoritative References & Bulletins</div>
                <div className="space-y-1 max-h-32 overflow-y-auto">
                  {selectedVuln.references.map((ref, idx) => (
                    <a
                      key={idx}
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center space-x-2 text-xs font-mono text-cyan-400 hover:text-cyan-300 hover:underline truncate p-1.5 rounded bg-slate-950/60 border border-slate-800"
                    >
                      <ExternalLink className="w-3 h-3 shrink-0" />
                      <span className="truncate">{ref}</span>
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* Close Button */}
            <div className="flex justify-end pt-3 border-t border-slate-800">
              <button
                onClick={() => setSelectedVuln(null)}
                className="px-5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-mono font-bold text-slate-200 transition-colors"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}

      {/* High-Tech Mesh Broadcast Propagation Modal (Retained) */}
      {showBroadcastModal && broadcastResult && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md animate-fadeIn">
          <div className="glass-panel w-full max-w-2xl rounded-2xl border border-cyan-500/50 shadow-2xl shadow-cyan-950/80 p-6 space-y-5">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center space-x-3">
                <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                  <Globe className="w-5 h-5 animate-pulse" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-slate-100 uppercase tracking-wide flex items-center space-x-2">
                    <span>P2P MESH BROADCAST CONFIRMED</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                      LIVE
                    </span>
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Behavioral threat vector safely disseminated across decentralized mesh with zero PII exposure.
                  </p>
                </div>
              </div>
              <button
                onClick={() => setShowBroadcastModal(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
              <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                <div className="text-[10px] text-slate-500 uppercase">Threat Vector</div>
                <div className="text-sm font-bold text-cyan-400 mt-1">{broadcastResult.pattern.patternCode}</div>
              </div>
              <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                <div className="text-[10px] text-slate-500 uppercase">Origin Node</div>
                <div className="text-xs font-bold text-slate-200 mt-1 truncate">{broadcastResult.sourceOrg?.name || 'Demo Bank'}</div>
              </div>
              <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                <div className="text-[10px] text-slate-500 uppercase">DLT Ledger</div>
                <div className="text-xs font-bold text-amber-400 mt-1">Block #{broadcastResult.ledgerBlock?.blockNumber || 10421}</div>
              </div>
              <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                <div className="text-[10px] text-slate-500 uppercase">Consensus</div>
                <div className="text-xs font-bold text-emerald-400 mt-1">4/4 Validators</div>
              </div>
            </div>

            <div className="space-y-2.5">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span className="uppercase font-bold tracking-wider text-slate-300">Peer Nodes Telemetry & Correlation</span>
                <span className="text-cyan-400 flex items-center space-x-1">
                  <Clock className="w-3 h-3" />
                  <span>Sub-second gossip propagation</span>
                </span>
              </div>

              <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                {broadcastResult.meshPropagation?.map((peer: any) => (
                  <div
                    key={peer.peerOrgId}
                    className={`p-3 rounded-xl border flex items-center justify-between font-mono text-xs transition-all ${
                      peer.earlyWarningTriggered
                        ? 'bg-rose-950/20 border-rose-800/80 shadow-sm shadow-rose-950/50'
                        : 'bg-slate-900/60 border-slate-800'
                    }`}
                  >
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-slate-100">{peer.peerOrgName}</span>
                        <span className="text-[10px] text-slate-500">({peer.peerType})</span>
                        <span className="text-[10px] text-slate-400 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">
                          {peer.latencyMs}ms
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400 flex items-center space-x-2">
                        <span>Matching Sequence:</span>
                        <span className="text-slate-300 font-semibold truncate max-w-xs">
                          {peer.matchingEvents?.join(' → ') || 'None (Healthy)'}
                        </span>
                      </div>
                    </div>

                    <div className="text-right space-y-1">
                      <div className={`text-sm font-black ${peer.similarityPercentage >= 65 ? 'text-rose-400' : 'text-slate-400'}`}>
                        {peer.similarityPercentage}% Match
                      </div>
                      <span
                        className={`inline-block text-[10px] px-2 py-0.5 rounded border font-bold ${
                          peer.earlyWarningTriggered
                            ? 'bg-rose-950 text-rose-300 border-rose-700 animate-pulse'
                            : 'bg-emerald-950 text-emerald-400 border-emerald-800'
                        }`}
                      >
                        {peer.earlyWarningTriggered ? '🚨 EARLY WARNING' : '✓ CLEARED'}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-3 border-t border-slate-800">
              <button
                onClick={() => navigate('/dlt-ledger')}
                className="w-full sm:w-auto px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs font-mono text-slate-300 flex items-center justify-center space-x-1.5"
              >
                <span>View DLT Ledger Block</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </button>

              <div className="flex items-center space-x-2 w-full sm:w-auto">
                <button
                  onClick={() => setShowBroadcastModal(false)}
                  className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200"
                >
                  Close
                </button>
                <button
                  onClick={() => {
                    setShowBroadcastModal(false);
                    navigate('/collaborative-network', { state: { broadcastData: broadcastResult } });
                  }}
                  className="px-5 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs shadow-lg glow-cyan flex items-center space-x-1.5"
                >
                  <span>Open Defense Mesh Visualizer</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
