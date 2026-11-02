import React, { useState, useEffect, useMemo } from 'react';
import {
  Landmark,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Server,
  Smartphone,
  CreditCard,
  Database,
  Monitor,
  Key,
  Network,
  RotateCcw,
  Search,
  Plus,
  Edit2,
  Trash2,
  RefreshCw,
  AlertTriangle,
  Building2,
  Lock,
  ArrowUpRight,
  Filter
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import { BankAsset } from '../types';

export const BankAssets: React.FC = () => {
  const { token, currentUser, addNotification } = useApp();

  const [assets, setAssets] = useState<BankAsset[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  // Modal States
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);
  const [editingAsset, setEditingAsset] = useState<BankAsset | null>(null);
  const [isDeleting, setIsDeleting] = useState<string | null>(null);
  const [resettingBaseline, setResettingBaseline] = useState<boolean>(false);

  // Form State
  const [formData, setFormData] = useState({
    name: '',
    category: 'Core Banking',
    description: '',
    criticality: 'HIGH' as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
    ipOrIdentifier: '',
    technologyStack: '',
    ownerDepartment: '',
    securityStatus: 'HEALTHY' as 'HEALTHY' | 'DEGRADED' | 'AT_RISK' | 'COMPROMISED' | 'MAINTENANCE',
    associatedVulnsCount: 0,
    riskScore: 25
  });

  const fetchAssets = async () => {
    if (!token) return;
    try {
      setLoading(true);
      const res = await fetch('/api/bank-assets', {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      if (res.ok) {
        const data = await res.json();
        setAssets(data.assets || []);
      }
    } catch (err) {
      console.error('Failed to fetch banking assets:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAssets();
  }, [token]);

  const handleOpenAddModal = () => {
    setEditingAsset(null);
    setFormData({
      name: '',
      category: 'Core Banking',
      description: '',
      criticality: 'HIGH',
      ipOrIdentifier: '10.10.x.x',
      technologyStack: '',
      ownerDepartment: 'IT Operations',
      securityStatus: 'HEALTHY',
      associatedVulnsCount: 0,
      riskScore: 25
    });
    setIsModalOpen(true);
  };

  const handleOpenEditModal = (asset: BankAsset) => {
    setEditingAsset(asset);
    setFormData({
      name: asset.name,
      category: asset.category,
      description: asset.description,
      criticality: asset.criticality,
      ipOrIdentifier: asset.ipOrIdentifier,
      technologyStack: asset.technologyStack,
      ownerDepartment: asset.ownerDepartment,
      securityStatus: asset.securityStatus,
      associatedVulnsCount: asset.associatedVulnsCount,
      riskScore: asset.riskScore
    });
    setIsModalOpen(true);
  };

  const handleSaveAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;

    try {
      if (editingAsset) {
        // Update existing asset
        const res = await fetch(`/api/bank-assets/${editingAsset.id}`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`
          },
          body: JSON.stringify(formData)
        });
        if (res.ok) {
          addNotification('Asset Updated', `Updated asset ${formData.name}`, 'SUCCESS');
          setIsModalOpen(false);
          fetchAssets();
        } else {
          const errData = await res.json();
          alert(`Error: ${errData.message || 'Failed to update asset'}`);
        }
      } else {
        // Create new asset
        const res = await fetch('/api/bank-assets', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`
          },
          body: JSON.stringify(formData)
        });
        if (res.ok) {
          addNotification('Asset Registered', `Registered banking asset ${formData.name}`, 'SUCCESS');
          setIsModalOpen(false);
          fetchAssets();
        } else {
          const errData = await res.json();
          alert(`Error: ${errData.message || 'Failed to create asset'}`);
        }
      }
    } catch (err) {
      console.error('Error saving asset:', err);
    }
  };

  const handleDeleteAsset = async (id: string, name: string) => {
    if (!token || !window.confirm(`Are you sure you want to delete ${name}?`)) return;
    setIsDeleting(id);
    try {
      const res = await fetch(`/api/bank-assets/${id}`, {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      if (res.ok) {
        addNotification('Asset Removed', `Deleted asset ${name}`, 'WARNING');
        fetchAssets();
      }
    } catch (err) {
      console.error('Failed to delete asset:', err);
    } finally {
      setIsDeleting(null);
    }
  };

  const handleResetBaseline = async () => {
    if (!token) return;
    setResettingBaseline(true);
    try {
      const res = await fetch('/api/bank-assets/reset-baseline', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      if (res.ok) {
        addNotification('Baseline Reset', '10 baseline banking assets & initial security events restored.', 'SUCCESS');
        fetchAssets();
      }
    } catch (err) {
      console.error('Error resetting baseline:', err);
    } finally {
      setResettingBaseline(false);
    }
  };

  // Filtered Assets
  const filteredAssets = useMemo(() => {
    return assets.filter((asset) => {
      const matchesSearch =
        asset.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        asset.ipOrIdentifier.toLowerCase().includes(searchTerm.toLowerCase()) ||
        asset.category.toLowerCase().includes(searchTerm.toLowerCase()) ||
        asset.ownerDepartment.toLowerCase().includes(searchTerm.toLowerCase());

      const matchesCategory = categoryFilter === 'ALL' || asset.category === categoryFilter;
      const matchesStatus = statusFilter === 'ALL' || asset.securityStatus === statusFilter;

      return matchesSearch && matchesCategory && matchesStatus;
    });
  }, [assets, searchTerm, categoryFilter, statusFilter]);

  // Statistics
  const stats = useMemo(() => {
    const total = assets.length;
    const critical = assets.filter((a) => a.criticality === 'CRITICAL').length;
    const compromisedOrAtRisk = assets.filter((a) => a.securityStatus === 'COMPROMISED' || a.securityStatus === 'AT_RISK').length;
    const avgRisk = total > 0 ? Math.round(assets.reduce((sum, a) => sum + a.riskScore, 0) / total) : 0;
    return { total, critical, compromisedOrAtRisk, avgRisk };
  }, [assets]);

  const categories = useMemo(() => {
    const set = new Set(assets.map((a) => a.category));
    return ['ALL', ...Array.from(set)];
  }, [assets]);

  const getCategoryIcon = (category: string) => {
    switch (category.toLowerCase()) {
      case 'core banking':
        return <Landmark className="w-4 h-4 text-cyan-400" />;
      case 'payment gateway':
        return <CreditCard className="w-4 h-4 text-purple-400" />;
      case 'atm infrastructure':
        return <Building2 className="w-4 h-4 text-amber-400" />;
      case 'mobile banking':
        return <Smartphone className="w-4 h-4 text-emerald-400" />;
      case 'customer database':
        return <Database className="w-4 h-4 text-rose-400" />;
      case 'workstations & endpoints':
        return <Monitor className="w-4 h-4 text-blue-400" />;
      case 'authentication server':
        return <Lock className="w-4 h-4 text-yellow-400" />;
      case 'internal network':
        return <Network className="w-4 h-4 text-indigo-400" />;
      default:
        return <Server className="w-4 h-4 text-slate-400" />;
    }
  };

  const getStatusBadge = (status: BankAsset['securityStatus']) => {
    switch (status) {
      case 'HEALTHY':
        return <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"><ShieldCheck className="w-3 h-3" /> Healthy</span>;
      case 'DEGRADED':
        return <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-yellow-500/10 text-yellow-400 border border-yellow-500/20"><AlertTriangle className="w-3 h-3" /> Degraded</span>;
      case 'AT_RISK':
        return <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20"><ShieldAlert className="w-3 h-3" /> At Risk</span>;
      case 'COMPROMISED':
        return <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20 animate-pulse"><AlertTriangle className="w-3 h-3" /> Compromised</span>;
      case 'MAINTENANCE':
        return <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-500/10 text-slate-400 border border-slate-500/20"><RefreshCw className="w-3 h-3" /> Maintenance</span>;
    }
  };

  const getCriticalityBadge = (criticality: BankAsset['criticality']) => {
    switch (criticality) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 rounded text-xs font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 rounded text-xs font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2 py-0.5 rounded text-xs font-bold bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">MEDIUM</span>;
      case 'LOW':
        return <span className="px-2 py-0.5 rounded text-xs font-bold bg-slate-500/20 text-slate-400 border border-slate-500/30">LOW</span>;
    }
  };

  const getRiskScoreColor = (score: number) => {
    if (score >= 80) return 'text-rose-400';
    if (score >= 65) return 'text-amber-400';
    if (score >= 45) return 'text-yellow-400';
    return 'text-emerald-400';
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-[#0F1420] via-[#121929] to-[#0F1420] p-6 rounded-2xl border border-cyan-500/20 shadow-xl">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Landmark className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white tracking-wide flex items-center gap-2">
                Demo Bank Asset Inventory
                <span className="text-xs px-2.5 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-medium">
                  Banking Security Edition
                </span>
              </h1>
              <p className="text-sm text-slate-400">
                Monitored critical infrastructure, real-time security posture & vulnerability exposure for Demo Bank (org-1)
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          <button
            onClick={fetchAssets}
            disabled={loading}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 text-slate-200 border border-slate-700 text-sm transition-all"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
            Refresh
          </button>

          {currentUser?.role === 'admin' && (
            <>
              <button
                onClick={handleResetBaseline}
                disabled={resettingBaseline}
                className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 text-sm transition-all"
              >
                <RotateCcw className={`w-4 h-4 ${resettingBaseline ? 'animate-spin' : ''}`} />
                Reset Baseline
              </button>

              <button
                onClick={handleOpenAddModal}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium text-sm shadow-lg shadow-cyan-500/20 transition-all"
              >
                <Plus className="w-4 h-4" />
                Add Banking Asset
              </button>
            </>
          )}
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#0F1420]/80 border border-slate-800/80 p-5 rounded-xl shadow-lg relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase tracking-wider text-slate-400 font-semibold">Total Monitored Assets</span>
            <Server className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white">{stats.total}</span>
            <span className="text-xs text-slate-400">banking systems</span>
          </div>
          <div className="mt-2 text-xs text-cyan-400/80 flex items-center gap-1">
            <span>100% telemetry coverage</span>
          </div>
        </div>

        <div className="bg-[#0F1420]/80 border border-slate-800/80 p-5 rounded-xl shadow-lg relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase tracking-wider text-slate-400 font-semibold">Critical Assets</span>
            <Shield className="w-5 h-5 text-rose-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-rose-400">{stats.critical}</span>
            <span className="text-xs text-slate-400">Tier-1 systems</span>
          </div>
          <div className="mt-2 text-xs text-rose-400/80 flex items-center gap-1">
            <span>CBS, Payment, Auth, CIF & DR</span>
          </div>
        </div>

        <div className="bg-[#0F1420]/80 border border-slate-800/80 p-5 rounded-xl shadow-lg relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase tracking-wider text-slate-400 font-semibold">Compromised / At Risk</span>
            <ShieldAlert className="w-5 h-5 text-amber-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-amber-400">{stats.compromisedOrAtRisk}</span>
            <span className="text-xs text-slate-400">require mitigation</span>
          </div>
          <div className="mt-2 text-xs text-amber-400/80 flex items-center gap-1">
            <span>Active containment in progress</span>
          </div>
        </div>

        <div className="bg-[#0F1420]/80 border border-slate-800/80 p-5 rounded-xl shadow-lg relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase tracking-wider text-slate-400 font-semibold">Average Asset Risk</span>
            <AlertTriangle className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className={`text-3xl font-extrabold ${getRiskScoreColor(stats.avgRisk)}`}>{stats.avgRisk}</span>
            <span className="text-xs text-slate-400">/ 100</span>
          </div>
          <div className="mt-2 text-xs text-slate-400 flex items-center gap-1">
            <span>Weighted banking exposure</span>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#0F1420]/80 border border-slate-800/80 p-4 rounded-xl flex flex-col md:flex-row gap-4 items-center justify-between shadow-lg">
        <div className="relative w-full md:w-96">
          <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Search by asset name, IP, department, or stack..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 rounded-lg bg-slate-900/90 border border-slate-700/80 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
          />
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto flex-wrap">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-slate-400" />
            <span className="text-xs text-slate-400 font-medium">Category:</span>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="bg-slate-900/90 border border-slate-700/80 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              {categories.map((c) => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 font-medium">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-slate-900/90 border border-slate-700/80 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Statuses</option>
              <option value="HEALTHY">Healthy</option>
              <option value="DEGRADED">Degraded</option>
              <option value="AT_RISK">At Risk</option>
              <option value="COMPROMISED">Compromised</option>
              <option value="MAINTENANCE">Maintenance</option>
            </select>
          </div>
        </div>
      </div>

      {/* Asset Table */}
      <div className="bg-[#0F1420]/80 border border-slate-800/80 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/50 text-slate-400 text-xs uppercase tracking-wider font-semibold">
                <th className="py-3.5 px-4">Banking Asset</th>
                <th className="py-3.5 px-4">Category</th>
                <th className="py-3.5 px-4">Criticality</th>
                <th className="py-3.5 px-4">IP / Endpoint</th>
                <th className="py-3.5 px-4">Technology Stack</th>
                <th className="py-3.5 px-4">Owner Dept</th>
                <th className="py-3.5 px-4">Status</th>
                <th className="py-3.5 px-4">Risk Score</th>
                <th className="py-3.5 px-4">Vulns</th>
                <th className="py-3.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredAssets.length === 0 ? (
                <tr>
                  <td colSpan={10} className="py-12 text-center text-slate-400">
                    <Server className="w-10 h-10 mx-auto mb-2 text-slate-600" />
                    <p className="font-medium text-slate-300">No banking assets match your criteria</p>
                    <p className="text-xs text-slate-500 mt-1">Try adjusting your search terms or filters</p>
                  </td>
                </tr>
              ) : (
                filteredAssets.map((asset) => (
                  <tr key={asset.id} className="hover:bg-slate-800/30 transition-colors group">
                    <td className="py-4 px-4">
                      <div>
                        <div className="font-semibold text-slate-100 flex items-center gap-2">
                          {asset.name}
                        </div>
                        <div className="text-xs text-slate-400 line-clamp-1 mt-0.5" title={asset.description}>
                          {asset.description}
                        </div>
                      </div>
                    </td>
                    <td className="py-4 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-1.5 text-xs text-slate-300">
                        {getCategoryIcon(asset.category)}
                        <span>{asset.category}</span>
                      </div>
                    </td>
                    <td className="py-4 px-4 whitespace-nowrap">
                      {getCriticalityBadge(asset.criticality)}
                    </td>
                    <td className="py-4 px-4 whitespace-nowrap font-mono text-xs text-cyan-400">
                      {asset.ipOrIdentifier}
                    </td>
                    <td className="py-4 px-4 text-xs text-slate-300 max-w-[180px] truncate" title={asset.technologyStack}>
                      {asset.technologyStack}
                    </td>
                    <td className="py-4 px-4 whitespace-nowrap text-xs text-slate-300">
                      {asset.ownerDepartment}
                    </td>
                    <td className="py-4 px-4 whitespace-nowrap">
                      {getStatusBadge(asset.securityStatus)}
                    </td>
                    <td className="py-4 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <span className={`font-bold font-mono text-sm ${getRiskScoreColor(asset.riskScore)}`}>
                          {asset.riskScore}
                        </span>
                        <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full ${
                              asset.riskScore >= 80 ? 'bg-rose-500' :
                              asset.riskScore >= 65 ? 'bg-amber-500' :
                              asset.riskScore >= 45 ? 'bg-yellow-500' : 'bg-emerald-500'
                            }`}
                            style={{ width: `${asset.riskScore}%` }}
                          />
                        </div>
                      </div>
                    </td>
                    <td className="py-4 px-4 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${
                        asset.associatedVulnsCount > 4 ? 'bg-rose-500/10 text-rose-400' :
                        asset.associatedVulnsCount > 0 ? 'bg-amber-500/10 text-amber-400' :
                        'bg-slate-800 text-slate-400'
                      }`}>
                        {asset.associatedVulnsCount} CVEs
                      </span>
                    </td>
                    <td className="py-4 px-4 whitespace-nowrap text-right">
                      {currentUser?.role === 'admin' && (
                        <div className="flex items-center justify-end gap-1.5 opacity-90 group-hover:opacity-100">
                          <button
                            onClick={() => handleOpenEditModal(asset)}
                            className="p-1.5 rounded hover:bg-slate-700/60 text-slate-400 hover:text-cyan-400 transition-colors"
                            title="Edit Asset"
                          >
                            <Edit2 className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => handleDeleteAsset(asset.id, asset.name)}
                            disabled={isDeleting === asset.id}
                            className="p-1.5 rounded hover:bg-rose-500/20 text-slate-400 hover:text-rose-400 transition-colors"
                            title="Delete Asset"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add / Edit Asset Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="bg-[#0F1420] border border-cyan-500/30 rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl">
            <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <Landmark className="w-5 h-5 text-cyan-400" />
                {editingAsset ? 'Edit Banking Asset' : 'Add New Banking Asset'}
              </h2>
              <button
                onClick={() => setIsModalOpen(false)}
                className="text-slate-400 hover:text-white text-lg font-bold"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleSaveAsset} className="p-6 space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">Asset Name</label>
                  <input
                    type="text"
                    required
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    placeholder="e.g. UPI Switch Cluster"
                    className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">Category</label>
                  <select
                    value={formData.category}
                    onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="Core Banking">Core Banking</option>
                    <option value="Internet Banking">Internet Banking</option>
                    <option value="Mobile Banking">Mobile Banking</option>
                    <option value="ATM Infrastructure">ATM Infrastructure</option>
                    <option value="Payment Gateway">Payment Gateway</option>
                    <option value="Customer Database">Customer Database</option>
                    <option value="Workstations & Endpoints">Workstations & Endpoints</option>
                    <option value="Authentication Server">Authentication Server</option>
                    <option value="Internal Network">Internal Network</option>
                    <option value="Disaster Recovery">Disaster Recovery</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">Criticality Level</label>
                  <select
                    value={formData.criticality}
                    onChange={(e) => setFormData({ ...formData, criticality: e.target.value as any })}
                    className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="CRITICAL">CRITICAL (Tier-1 Banking Service)</option>
                    <option value="HIGH">HIGH (Vital Infrastructure)</option>
                    <option value="MEDIUM">MEDIUM (Operational Support)</option>
                    <option value="LOW">LOW (Peripheral Service)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">Security Status</label>
                  <select
                    value={formData.securityStatus}
                    onChange={(e) => setFormData({ ...formData, securityStatus: e.target.value as any })}
                    className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="HEALTHY">HEALTHY</option>
                    <option value="DEGRADED">DEGRADED</option>
                    <option value="AT_RISK">AT_RISK</option>
                    <option value="COMPROMISED">COMPROMISED</option>
                    <option value="MAINTENANCE">MAINTENANCE</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">IP Address / Identifier</label>
                  <input
                    type="text"
                    required
                    value={formData.ipOrIdentifier}
                    onChange={(e) => setFormData({ ...formData, ipOrIdentifier: e.target.value })}
                    placeholder="e.g. 10.10.1.50"
                    className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-sm text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">Technology Stack</label>
                  <input
                    type="text"
                    required
                    value={formData.technologyStack}
                    onChange={(e) => setFormData({ ...formData, technologyStack: e.target.value })}
                    placeholder="e.g. RHEL 9 / Finacle Core"
                    className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">Owner Department</label>
                  <input
                    type="text"
                    required
                    value={formData.ownerDepartment}
                    onChange={(e) => setFormData({ ...formData, ownerDepartment: e.target.value })}
                    placeholder="e.g. Payment Operations"
                    className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">Risk Score (0 - 100)</label>
                  <input
                    type="number"
                    min="0"
                    max="100"
                    required
                    value={formData.riskScore}
                    onChange={(e) => setFormData({ ...formData, riskScore: parseInt(e.target.value, 10) || 0 })}
                    className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-sm text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase mb-1">Description</label>
                <textarea
                  rows={2}
                  required
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  placeholder="Operational purpose, connected enclaves, or compliance boundary..."
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="pt-4 border-t border-slate-800 flex justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium text-sm shadow-lg shadow-cyan-500/20 transition-all"
                >
                  {editingAsset ? 'Save Changes' : 'Create Asset'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
