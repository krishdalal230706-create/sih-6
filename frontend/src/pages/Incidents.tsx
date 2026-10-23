import React, { useState } from 'react';
import {
  AlertTriangle,
  Clock,
  Shield,
  Eye,
  CheckCircle2,
  X,
  Activity,
  ArrowRight,
  Plus,
  Zap
} from 'lucide-react';
import { useApp } from '../context/AppContext';
import { Incident } from '../types';

export const Incidents: React.FC = () => {
  const { incidents, updateIncidentStatus, executeResponseAction, responseActions, activeOrg } = useApp();
  
  // Filter incidents to show only current org's incidents
  const orgIncidents = React.useMemo(() => {
    if (!activeOrg) return incidents;
    return incidents.filter((i) => i.orgId === activeOrg.id);
  }, [incidents, activeOrg]);

  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(orgIncidents[0] || null);
  const [filterStatus, setFilterStatus] = useState<string>('ALL');
  const [newTimelineTitle, setNewTimelineTitle] = useState<string>('');

  // Update selected incident when org changes
  React.useEffect(() => {
    setSelectedIncident(orgIncidents[0] || null);
  }, [activeOrg?.id]);

  const filteredIncidents = filterStatus === 'ALL'
    ? orgIncidents
    : orgIncidents.filter((i) => i.status.toUpperCase() === filterStatus);

  const handleAddTimelineNote = () => {
    if (!newTimelineTitle.trim() || !selectedIncident) return;
    const newEvt = {
      id: `t-${Date.now()}`,
      time: new Date().toTimeString().slice(0, 8),
      title: newTimelineTitle.trim(),
      description: 'Investigator note logged to official incident record.',
      type: 'INVESTIGATION' as const
    };
    const updated = {
      ...selectedIncident,
      timeline: [...selectedIncident.timeline, newEvt]
    };
    setSelectedIncident(updated);
    setNewTimelineTitle('');
  };

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 sm:space-y-8 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-100 uppercase">INCIDENT MANAGEMENT</h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time security incident response queue, blast radius containment, and remediation tracking.
          </p>
        </div>

        <div className="flex items-center space-x-2 text-xs font-mono">
          <span className="px-3 py-1 rounded bg-rose-950 text-rose-400 border border-rose-800 font-bold">
            {incidents.filter(i => i.severity === 'CRITICAL' && i.status !== 'Resolved').length} Active Critical
          </span>
          <span className="px-3 py-1 rounded bg-slate-900 text-slate-400 border border-slate-800">
            {activeOrg?.name}
          </span>
        </div>
      </div>

      {/* Status Filter Tabs */}
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 pb-3 text-xs font-mono">
        {['ALL', 'DETECTED', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'].map((st) => (
          <button
            key={st}
            onClick={() => setFilterStatus(st)}
            className={`px-3 py-1.5 rounded-lg transition-all font-bold ${
              filterStatus === st
                ? 'bg-cyan-950 text-cyan-400 border border-cyan-800'
                : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
            }`}
          >
            {st}
          </button>
        ))}
      </div>

      {/* Incident List & Inspection Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Incident List */}
        <div className="lg:col-span-2 glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">LOGGED INCIDENTS</h3>
            <span className="text-xs font-mono text-cyan-400">{filteredIncidents.length} Records</span>
          </div>

          <div className="space-y-3">
            {filteredIncidents.map((inc) => (
              <div
                key={inc.id}
                onClick={() => setSelectedIncident(inc)}
                className={`p-4 rounded-xl border cursor-pointer transition-all ${
                  selectedIncident?.id === inc.id
                    ? 'bg-slate-900 border-cyan-500/80 shadow-lg shadow-cyan-950/40'
                    : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <span className="font-mono text-xs font-bold text-cyan-400">{inc.incidentId}</span>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                        inc.status === 'Detected'
                          ? 'bg-rose-950 text-rose-400 border-rose-800'
                          : inc.status === 'Investigating'
                          ? 'bg-amber-950 text-amber-400 border-amber-800'
                          : inc.status === 'Contained'
                          ? 'bg-blue-950 text-blue-400 border-blue-800'
                          : 'bg-emerald-950 text-emerald-400 border-emerald-800'
                      }`}
                    >
                      {inc.status}
                    </span>
                  </div>

                  <span className="text-xs font-mono text-slate-400">Confidence: {inc.confidence}%</span>
                </div>

                <h4 className="text-sm font-bold text-slate-100 mt-2">{inc.title}</h4>
                <p className="text-xs text-slate-400 mt-1 line-clamp-2">{inc.description}</p>

                <div className="flex items-center justify-between mt-3 text-[11px] font-mono text-slate-500 pt-2 border-t border-slate-800/80">
                  <span>Detected: {inc.detectionTime}</span>
                  <span className="text-rose-400 font-bold">Impact Risk: {inc.riskScore}/100</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Selected Incident Drawer */}
        {selectedIncident && (
          <div className="glass-panel p-6 rounded-2xl border border-cyan-500/30 space-y-6">
            <div className="flex items-start justify-between gap-2 border-b border-slate-800 pb-3">
              <div className="min-w-0 flex-1">
                <span className="font-mono text-xs font-bold text-cyan-400">{selectedIncident.incidentId}</span>
                <h3 className="text-base font-bold text-slate-100 truncate">{selectedIncident.title}</h3>
              </div>
              <span className="px-2.5 py-1 rounded bg-rose-950 text-rose-400 text-xs font-mono font-bold border border-rose-800 shrink-0">
                {selectedIncident.severity}
              </span>
            </div>

            {/* Change Incident Status Control */}
            <div className="space-y-1">
              <label className="block text-[10px] font-mono text-slate-400 uppercase">Change Incident Lifecycle Status</label>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5 text-[10px] font-mono">
                {(['Detected', 'Investigating', 'Contained', 'Resolved'] as const).map((st) => (
                  <button
                    key={st}
                    onClick={() => updateIncidentStatus(selectedIncident.id, st)}
                    className={`py-1.5 px-1 rounded font-bold border transition-all truncate ${
                      selectedIncident.status === st
                        ? 'bg-cyan-500 text-slate-950 border-cyan-400'
                        : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200'
                    }`}
                  >
                    {st}
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-3 text-xs">
              <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                <div className="text-[10px] font-mono text-slate-500 uppercase">Affected Asset</div>
                <div className="text-slate-200 font-semibold">{selectedIncident.affectedAsset}</div>
              </div>

              <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                <div className="text-[10px] font-mono text-slate-500 uppercase">Description</div>
                <p className="text-slate-300">{selectedIncident.description}</p>
              </div>
            </div>

            {/* Investigation Timeline */}
            <div className="space-y-3">
              <div className="text-xs font-mono text-cyan-400 uppercase tracking-wider font-bold">
                INVESTIGATION TIMELINE RECORD
              </div>
              <div className="space-y-3 border-l border-slate-800 pl-4 ml-2">
                {selectedIncident.timeline.map((t) => (
                  <div key={t.id} className="relative">
                    <span className="absolute -left-[21px] top-1 w-2.5 h-2.5 rounded-full bg-cyan-400 ring-4 ring-slate-950"></span>
                    <div className="text-[10px] font-mono text-slate-500">{t.time}</div>
                    <div className="text-xs font-bold text-slate-200">{t.title}</div>
                    <div className="text-[11px] text-slate-400">{t.description}</div>
                  </div>
                ))}
              </div>

              {/* Add Note to Timeline */}
              <div className="flex items-center space-x-2 pt-2">
                <input
                  type="text"
                  placeholder="Add investigator note to timeline..."
                  value={newTimelineTitle}
                  onChange={(e) => setNewTimelineTitle(e.target.value)}
                  className="flex-1 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                />
                <button
                  onClick={handleAddTimelineNote}
                  className="px-3 py-1.5 rounded-lg bg-cyan-500 text-slate-950 font-bold text-xs shrink-0"
                >
                  Add Note
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
