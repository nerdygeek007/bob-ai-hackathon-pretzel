import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  AlertTriangle,
  Flame,
  CheckCircle2,
  Database,
  RefreshCw,
  Clock,
  Layers,
  ArrowUpRight,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell,
} from 'recharts';
import { useSentinel } from '../../store/sentinelStore';
import { Card } from '../../components/ui/Card';
import { SeverityBadge } from '../../components/ui/SeverityBadge';
import { overviewTimelineData, priorityDistributionData } from '../../data/mockNormalization';
import { Incident } from '../../types';

export const OverviewPage: React.FC = () => {
  const navigate = useNavigate();
  const { incidents, domains, activeSourcesCount, totalSourcesCount, setSelectedIncidentId } =
    useSentinel();

  // Metrics computation
  const criticalCount = incidents.filter((i) => i.priority === 'CRITICAL').length;
  const highCount = incidents.filter((i) => i.priority === 'HIGH').length;
  const mediumCount = incidents.filter((i) => i.priority === 'MEDIUM').length;
  const lowCount = incidents.filter((i) => i.priority === 'LOW').length;
  const falsePositivesCount = incidents.filter(
    (i) => i.threatAssessment === 'LIKELY_FALSE_POSITIVE'
  ).length;

  const totalEventsProcessed = domains.reduce((acc, d) => acc + d.totalRecords, 0);

  const handleRowClick = (incident: Incident) => {
    setSelectedIncidentId(incident.incidentId);
    navigate(`/incidents/${incident.incidentId}`);
  };

  return (
    <div className="space-y-6">
      {/* Top Header Banner */}
      <div className="bg-[#111827] border border-[#1f293d] rounded-sm p-5 shadow-lg flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold font-mono text-slate-100 uppercase tracking-wide">
              SENTINEL-X COMMAND CENTER
            </h1>
            <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-cyan-950 text-cyan-400 border border-cyan-800">
              OPERATIONAL SOC
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Threat Intelligence Correlation & Alert Prioritisation Assistant
          </p>
        </div>

        {/* System Meta telemetry chips */}
        <div className="flex flex-wrap items-center gap-3 text-xs font-mono">
          <div className="bg-slate-900/90 border border-slate-800 px-3 py-2 rounded">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block">
              System Status
            </span>
            <span className="font-bold text-emerald-400 flex items-center gap-1.5 mt-0.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.8)]" />
              OPERATIONAL
            </span>
          </div>

          <div className="bg-slate-900/90 border border-slate-800 px-3 py-2 rounded">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block">
              Active Data Sources
            </span>
            <span className="font-bold text-cyan-400 mt-0.5 block">
              {activeSourcesCount} / {totalSourcesCount} Online
            </span>
          </div>

          <div className="bg-slate-900/90 border border-slate-800 px-3 py-2 rounded">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block">
              Events Processed
            </span>
            <span className="font-bold text-slate-200 mt-0.5 block">
              {totalEventsProcessed.toLocaleString()}
            </span>
          </div>

          <div className="bg-slate-900/90 border border-slate-800 px-3 py-2 rounded">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block">
              Last Cycle
            </span>
            <span className="font-bold text-slate-300 flex items-center gap-1 mt-0.5">
              <Clock className="w-3 h-3 text-slate-400" />
              12s ago
            </span>
          </div>
        </div>
      </div>

      {/* KPI Cards: Critical, High, Medium, Low, Correlated, Likely False Positive */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3.5">
        <div className="bg-[#111827] border border-red-900/40 rounded-sm p-4 relative overflow-hidden shadow">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase tracking-wider text-red-400 font-bold">
              CRITICAL
            </span>
            <Flame className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-black font-mono text-red-200 mt-2">{criticalCount}</div>
          <p className="text-[10px] text-slate-500 font-mono mt-1">Requires immediate BLUF</p>
          <div className="absolute top-0 right-0 w-16 h-16 bg-red-500/5 rounded-full blur-xl pointer-events-none" />
        </div>

        <div className="bg-[#111827] border border-orange-900/40 rounded-sm p-4 relative overflow-hidden shadow">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase tracking-wider text-orange-400 font-bold">
              HIGH
            </span>
            <AlertTriangle className="w-4 h-4 text-orange-400" />
          </div>
          <div className="text-2xl font-black font-mono text-orange-200 mt-2">{highCount}</div>
          <p className="text-[10px] text-slate-500 font-mono mt-1">Elevated risk correlation</p>
        </div>

        <div className="bg-[#111827] border border-amber-900/40 rounded-sm p-4 relative overflow-hidden shadow">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase tracking-wider text-amber-400 font-bold">
              MEDIUM
            </span>
            <ShieldAlert className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-black font-mono text-amber-200 mt-2">{mediumCount}</div>
          <p className="text-[10px] text-slate-500 font-mono mt-1">Under observation</p>
        </div>

        <div className="bg-[#111827] border border-emerald-900/40 rounded-sm p-4 relative overflow-hidden shadow">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase tracking-wider text-emerald-400 font-bold">
              LOW
            </span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-black font-mono text-emerald-200 mt-2">{lowCount}</div>
          <p className="text-[10px] text-slate-500 font-mono mt-1">Routine anomalies</p>
        </div>

        <div className="bg-[#111827] border border-cyan-900/40 rounded-sm p-4 relative overflow-hidden shadow">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase tracking-wider text-cyan-400 font-bold">
              CORRELATED
            </span>
            <Layers className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-black font-mono text-cyan-200 mt-2">{incidents.length}</div>
          <p className="text-[10px] text-slate-500 font-mono mt-1">Multi-domain clusters</p>
        </div>

        <div className="bg-[#111827] border border-slate-700/50 rounded-sm p-4 relative overflow-hidden shadow">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-bold">
              FALSE POSITIVES
            </span>
            <CheckCircle2 className="w-4 h-4 text-slate-400" />
          </div>
          <div className="text-2xl font-black font-mono text-slate-300 mt-2">
            {falsePositivesCount}
          </div>
          <p className="text-[10px] text-slate-500 font-mono mt-1">AI Discard / Benign</p>
        </div>
      </div>

      {/* Charts Section: A. Threat Timeline | B. Priority Dist | C. Domain Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* A. Threat Activity Timeline */}
        <div className="lg:col-span-6">
          <Card
            title="A. Threat Activity Timeline"
            subtitle="Ingestion volume across primary operational domains"
          >
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={overviewTimelineData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="siemGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#38bdf8" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="satGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#c084fc" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#c084fc" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="sensGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#4ade80" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#4ade80" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#475569" fontSize={10} fontStyle="italic" />
                  <YAxis stroke="#475569" fontSize={10} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#1e293b',
                      borderRadius: 4,
                      fontSize: 11,
                      fontFamily: 'JetBrains Mono',
                    }}
                  />
                  <Area type="monotone" dataKey="siem" name="SIEM" stroke="#38bdf8" fillOpacity={1} fill="url(#siemGrad)" />
                  <Area type="monotone" dataKey="satellite" name="Satellite" stroke="#c084fc" fillOpacity={1} fill="url(#satGrad)" />
                  <Area type="monotone" dataKey="sensors" name="Sensors" stroke="#4ade80" fillOpacity={1} fill="url(#sensGrad)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
            <div className="flex items-center justify-center gap-6 mt-2 pt-2 border-t border-slate-800 text-xs font-mono">
              <span className="flex items-center gap-1.5 text-sky-400">
                <span className="w-2.5 h-2.5 bg-sky-400 rounded-xs" /> SIEM
              </span>
              <span className="flex items-center gap-1.5 text-purple-400">
                <span className="w-2.5 h-2.5 bg-purple-400 rounded-xs" /> SATELLITE / SPACE
              </span>
              <span className="flex items-center gap-1.5 text-emerald-400">
                <span className="w-2.5 h-2.5 bg-emerald-400 rounded-xs" /> SENSORS
              </span>
            </div>
          </Card>
        </div>

        {/* B. Priority Distribution */}
        <div className="lg:col-span-3">
          <Card title="B. Priority Distribution" subtitle="Computed Sentinel-X Priority">
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={priorityDistributionData} margin={{ top: 20, right: 10, left: -25, bottom: 0 }}>
                  <XAxis dataKey="priority" stroke="#475569" fontSize={9} />
                  <YAxis stroke="#475569" fontSize={10} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#1e293b',
                      borderRadius: 4,
                      fontSize: 11,
                      fontFamily: 'JetBrains Mono',
                    }}
                  />
                  <Bar dataKey="count" radius={[2, 2, 0, 0]}>
                    {priorityDistributionData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
            <div className="text-[10px] text-center text-slate-400 font-mono mt-2 pt-2 border-t border-slate-800">
              Explainable Risk Engine Allocation
            </div>
          </Card>
        </div>

        {/* C. Evidence Source Activity (The 3 Primary Domains) */}
        <div className="lg:col-span-3">
          <Card
            title="C. Evidence Stream Activity"
            subtitle="The 3 primary evidence domains"
          >
            <div className="space-y-4 py-2 font-mono text-xs">
              {domains.map((dom) => {
                const activeInDom = dom.sources.filter((s) => s.enabled).length;
                const totalInDom = dom.sources.length;
                const percent = Math.round((dom.totalRecords / totalEventsProcessed) * 100) || 0;

                return (
                  <div key={dom.id} className="p-3 bg-slate-900/60 rounded border border-slate-800/80">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-1.5">
                        <span
                          className={`w-2 h-2 rounded-full ${
                            dom.enabled ? 'bg-emerald-400' : 'bg-slate-500'
                          }`}
                        />
                        <span className="font-bold text-slate-200">{dom.label}</span>
                      </div>
                      <span className="text-[10px] text-cyan-400">
                        {activeInDom}/{totalInDom} active
                      </span>
                    </div>

                    <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400">
                      <span>{dom.totalRecords.toLocaleString()} events</span>
                      <span className="font-bold text-slate-300">{percent}%</span>
                    </div>

                    <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden mt-1.5">
                      <div
                        className={`h-full ${
                          dom.id === 'SIEM'
                            ? 'bg-sky-400'
                            : dom.id === 'SATELLITE_SPACE'
                            ? 'bg-purple-400'
                            : 'bg-emerald-400'
                        }`}
                        style={{ width: `${percent}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
            <p className="text-[10px] text-slate-500 italic mt-2 text-center">
              MITRE ATT&CK & CISA KEV act strictly as enrichment sources.
            </p>
          </Card>
        </div>
      </div>

      {/* D. Recent Prioritized Incidents Table */}
      <Card
        title="D. Recent Prioritized Incidents"
        subtitle="Correlated multi-source security incidents"
        headerAction={
          <button
            onClick={() => navigate('/incidents')}
            className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
          >
            View All Correlated Incidents <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        }
        noPadding
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="border-b border-[#1f293d] bg-slate-900/60 text-slate-400 text-[11px] uppercase tracking-wider font-semibold">
                <th className="py-3 px-4">Incident ID</th>
                <th className="py-3 px-4">Priority</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4">Affected Asset</th>
                <th className="py-3 px-4">Evidence Sources</th>
                <th className="py-3 px-4">MITRE Techniques</th>
                <th className="py-3 px-4">First Seen</th>
                <th className="py-3 px-4">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e293b]/60">
              {incidents.map((inc) => (
                <tr
                  key={inc.incidentId}
                  onClick={() => handleRowClick(inc)}
                  className="hover:bg-slate-800/50 cursor-pointer transition-colors"
                >
                  <td className="py-3 px-4 font-bold text-cyan-400">{inc.incidentId}</td>
                  <td className="py-3 px-4">
                    <SeverityBadge severity={inc.priority} size="sm" variant="sentinel" />
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-slate-100">{inc.riskScore}</span>
                      <span className="text-[10px] text-slate-500">/ 100</span>
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <span className="text-cyan-300 font-semibold">{inc.confidence}%</span>
                  </td>
                  <td className="py-3 px-4 font-semibold text-slate-200">{inc.affectedAsset}</td>
                  <td className="py-3 px-4">
                    <div className="flex flex-wrap gap-1">
                      {inc.evidenceDomains.map((dom) => (
                        <span
                          key={dom}
                          className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700 font-bold"
                        >
                          {dom}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex flex-wrap gap-1">
                      {inc.mitreIds.map((tid) => (
                        <span
                          key={tid}
                          className="px-1.5 py-0.5 rounded text-[10px] bg-cyan-950/60 text-cyan-400 border border-cyan-800"
                        >
                          {tid}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="py-3 px-4 text-slate-400">
                    {new Date(inc.firstSeen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </td>
                  <td className="py-3 px-4">
                    <span className="text-[10px] px-2 py-0.5 rounded font-bold bg-slate-800 text-slate-300 border border-slate-700">
                      {inc.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};
