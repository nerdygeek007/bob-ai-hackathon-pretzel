import React, { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ArrowRight,
  ShieldAlert,
  Flame,
  CheckCircle2,
  Cpu,
  Layers,
  Activity,
  Radio,
  ExternalLink,
  AlertTriangle,
  Clock,
} from 'lucide-react';
import { useSentinel } from '../../store/sentinelStore';
import { Card } from '../../components/ui/Card';
import { SeverityBadge } from '../../components/ui/SeverityBadge';
import { DrawerPanel } from '../../components/ui/DrawerPanel';
import { Alert } from '../../types';
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import {
  overviewTimelineData,
  priorityDistributionData,
} from '../../data/mockNormalization';

export const OverviewPage: React.FC = () => {
  const navigate = useNavigate();
  const {
    alerts,
    incidents,
    eventsPerSec,
    totalEventsProcessed,
    processingLatencyMs,
    setSelectedIncidentId,
    updateAlertStatus,
  } = useSentinel();

  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);

  // Dynamic priority distribution derived from live alerts
  const dynamicPriorityDistribution = useMemo(() => {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    alerts.forEach((a) => {
      const p = a.priority || a.sourceSeverity || 'LOW';
      if (p === 'CRITICAL') counts.CRITICAL++;
      else if (p === 'HIGH') counts.HIGH++;
      else if (p === 'MEDIUM') counts.MEDIUM++;
      else counts.LOW++;
    });
    return [
      { priority: 'CRITICAL', count: counts.CRITICAL, color: '#dc2626' },
      { priority: 'HIGH', count: counts.HIGH, color: '#ea580c' },
      { priority: 'MEDIUM', count: counts.MEDIUM, color: '#d97706' },
      { priority: 'LOW', count: counts.LOW, color: '#2563eb' },
    ];
  }, [alerts]);

  // Top metric computations
  const totalAlertsCount = alerts.length;
  const highPriorityCount = alerts.filter(
    (a) => a.priority === 'HIGH' || a.priority === 'CRITICAL'
  ).length;
  const activeIncidentsCount = incidents.filter(
    (i) => i.status !== 'RESOLVED' && i.status !== 'CLOSED'
  ).length;

  // Most important incident (INC-1042)
  const topIncident = incidents.find((i) => i.incidentId === 'INC-1042') || incidents[0];

  const handleRowClick = (alert: Alert) => {
    setSelectedAlert(alert);
  };

  const handleIncidentClick = (incidentId: string) => {
    setSelectedIncidentId(incidentId);
    navigate(`/incidents/${incidentId}`);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#171717]">
            Overview
          </h1>
          <p className="text-sm text-[#737373] mt-0.5">
            Real-time threat detection, MITRE correlation, and prioritized security alerts
          </p>
        </div>

        {/* 10-Second Concept Flow Strip */}
        <div className="hidden xl:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#f9fafb] border border-[#e5e5e5] text-xs">
          <span className="text-[11px] font-semibold text-[#171717]">Core Flow:</span>
          <span className="text-[#737373]">Live Events</span>
          <span className="text-[#a3a3a3]">→</span>
          <span className="text-[#737373]">ML Correlation</span>
          <span className="text-[#a3a3a3]">→</span>
          <span className="text-[#737373]">MITRE Mapping</span>
          <span className="text-[#a3a3a3]">→</span>
          <span className="font-semibold text-blue-600">Actionable Alert</span>
        </div>
      </div>

      {/* Top 4 Core Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1: Events Processed */}
        <div className="bg-white border border-[#e5e5e5] rounded-xl p-4 shadow-[0_1px_2px_rgba(0,0,0,0.03)] flex flex-col justify-between">
          <span className="text-xs font-medium uppercase tracking-wider text-[#737373]">
            Events Processed
          </span>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold tracking-tight text-[#171717] font-mono">
              {eventsPerSec.toLocaleString()}
            </span>
            <span className="text-xs text-[#737373]">/ sec</span>
          </div>
          <p className="text-[11px] text-[#737373] mt-1">
            {totalEventsProcessed.toLocaleString()} total • {processingLatencyMs}ms latency
          </p>
        </div>

        {/* Metric 2: Alerts Detected */}
        <div className="bg-white border border-[#e5e5e5] rounded-xl p-4 shadow-[0_1px_2px_rgba(0,0,0,0.03)] flex flex-col justify-between">
          <span className="text-xs font-medium uppercase tracking-wider text-[#737373]">
            Alerts Detected
          </span>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold tracking-tight text-[#171717] font-mono">
              {totalAlertsCount}
            </span>
            <span className="text-xs text-[#737373]">total</span>
          </div>
          <p className="text-[11px] text-[#737373] mt-1">
            Correlated across 3 evidence streams
          </p>
        </div>

        {/* Metric 3: High Priority */}
        <div className="bg-white border border-[#e5e5e5] rounded-xl p-4 shadow-[0_1px_2px_rgba(0,0,0,0.03)] flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium uppercase tracking-wider text-[#737373]">
              High Priority
            </span>
            <span className="w-2 h-2 rounded-full bg-orange-500 animate-pulse" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold tracking-tight text-orange-600 font-mono">
              {highPriorityCount}
            </span>
            <span className="text-xs text-orange-700/80 font-medium">requiring triage</span>
          </div>
          <p className="text-[11px] text-[#737373] mt-1">
            Escalated by Sentinel-X risk policy
          </p>
        </div>

        {/* Metric 4: Active Incidents */}
        <div className="bg-white border border-[#e5e5e5] rounded-xl p-4 shadow-[0_1px_2px_rgba(0,0,0,0.03)] flex flex-col justify-between">
          <span className="text-xs font-medium uppercase tracking-wider text-[#737373]">
            Active Incidents
          </span>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-2xl font-bold tracking-tight text-[#171717] font-mono">
              {activeIncidentsCount}
            </span>
            <span className="text-xs text-[#737373]">multi-source</span>
          </div>
          <p className="text-[11px] text-[#737373] mt-1">
            Top: Possible Multi-Stage Attack
          </p>
        </div>
      </div>

      {/* Analytics & Activity Charts: Threat Timeline (8 cols) & Priority Distribution (4 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Threat Activity Timeline Chart (8 cols) */}
        <div className="lg:col-span-8">
          <Card
            title="Threat Activity Timeline"
            subtitle="Correlated event volume across SIEM, Satellite, and Sensor domains"
            headerAction={
              <div className="flex items-center gap-3 text-xs text-[#737373]">
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-blue-600 inline-block" /> SIEM
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-purple-500 inline-block" /> Satellite
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block" /> Sensors
                </span>
              </div>
            }
          >
            <div className="h-[220px] w-full pt-2">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  data={overviewTimelineData}
                  margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                >
                  <defs>
                    <linearGradient id="colorSiem" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#2563eb" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#2563eb" stopOpacity={0.0} />
                    </linearGradient>
                    <linearGradient id="colorSat" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#a855f7" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#a855f7" stopOpacity={0.0} />
                    </linearGradient>
                    <linearGradient id="colorSensors" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10b981" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <XAxis
                    dataKey="time"
                    stroke="#a3a3a3"
                    fontSize={11}
                    tickLine={false}
                    axisLine={{ stroke: '#e5e5e5' }}
                  />
                  <YAxis
                    stroke="#a3a3a3"
                    fontSize={11}
                    tickLine={false}
                    axisLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#ffffff',
                      borderColor: '#e5e5e5',
                      borderRadius: '8px',
                      fontSize: '12px',
                      boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.05)',
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="siem"
                    name="SIEM"
                    stroke="#2563eb"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorSiem)"
                  />
                  <Area
                    type="monotone"
                    dataKey="satellite"
                    name="Satellite"
                    stroke="#a855f7"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorSat)"
                  />
                  <Area
                    type="monotone"
                    dataKey="sensors"
                    name="Sensors"
                    stroke="#10b981"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorSensors)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </Card>
        </div>

        {/* Priority Distribution Bar Chart (4 cols) */}
        <div className="lg:col-span-4">
          <Card
            title="Priority Distribution"
            subtitle="Sentinel-X risk triage breakdown"
          >
            <div className="h-[220px] w-full pt-2">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={dynamicPriorityDistribution}
                  margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
                >
                  <XAxis
                    dataKey="priority"
                    stroke="#a3a3a3"
                    fontSize={10}
                    tickLine={false}
                    axisLine={{ stroke: '#e5e5e5' }}
                  />
                  <YAxis
                    stroke="#a3a3a3"
                    fontSize={11}
                    tickLine={false}
                    axisLine={false}
                    allowDecimals={false}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#ffffff',
                      borderColor: '#e5e5e5',
                      borderRadius: '8px',
                      fontSize: '12px',
                      boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.05)',
                    }}
                  />
                  <Bar dataKey="count" name="Alerts" radius={[4, 4, 0, 0]}>
                    {dynamicPriorityDistribution.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Card>
        </div>
      </div>

      {/* Main Content Layout: Left (Recent Alerts) | Right (Pipeline & Top Incident) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* LEFT / LARGE SECTION (8 cols): Recent Alerts */}
        <div className="lg:col-span-8">
          <Card
            title="Recent Alerts"
            subtitle="Prioritized threat detections across active data streams"
            headerAction={
              <button
                onClick={() => navigate('/alerts')}
                className="text-xs font-semibold text-blue-600 hover:text-blue-700 flex items-center gap-1 cursor-pointer transition-colors"
              >
                View all alerts <ArrowRight className="w-3.5 h-3.5" />
              </button>
            }
            noPadding
          >
            <div className="overflow-x-auto">
              <table className="w-full min-w-[620px] text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-[#e5e5e5] bg-[#f9fafb] text-[#737373] text-[11px] font-medium">
                    <th className="py-3 px-4">Severity</th>
                    <th className="py-3 px-4">Alert</th>
                    <th className="py-3 px-4">Source</th>
                    <th className="py-3 px-4">MITRE</th>
                    <th className="py-3 px-4">Confidence</th>
                    <th className="py-3 px-4">Priority</th>
                    <th className="py-3 px-4 text-right">Time</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#e5e5e5]">
                  {alerts.slice(0, 6).map((alert) => (
                    <tr
                      key={alert.alertId}
                      onClick={() => handleRowClick(alert)}
                      className="hover:bg-[#f9fafb] cursor-pointer transition-colors"
                    >
                      <td className="py-3 px-4">
                        <SeverityBadge severity={alert.sourceSeverity} size="sm" variant="source" />
                      </td>
                      <td className="py-3 px-4">
                        <div className="font-medium text-[#171717]">
                          {alert.title || alert.eventType}
                        </div>
                        <div className="text-[11px] text-[#737373] font-mono mt-0.5">
                          {alert.asset || alert.indicator || alert.alertId}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-[#737373]">
                        {alert.domain === 'SIEM' ? 'SIEM' : alert.domain === 'SATELLITE_SPACE' ? 'Satellite' : 'Sensors'}
                      </td>
                      <td className="py-3 px-4">
                        {alert.mitreId ? (
                          <span className="font-mono text-[11px] px-2 py-0.5 rounded-md bg-[#f5f5f5] text-[#171717] border border-[#e5e5e5]">
                            {alert.mitreId}
                          </span>
                        ) : (
                          <span className="text-[#a3a3a3]">—</span>
                        )}
                      </td>
                      <td className="py-3 px-4 font-mono font-medium text-[#171717]">
                        {alert.confidence ? `${alert.confidence}%` : '—'}
                      </td>
                      <td className="py-3 px-4">
                        <SeverityBadge severity={alert.priority || alert.sourceSeverity} size="sm" variant="sentinel" />
                      </td>
                      <td className="py-3 px-4 text-right text-[#737373] whitespace-nowrap">
                        {Math.floor((Date.now() - new Date(alert.timestamp).getTime()) / 60000)}m ago
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </div>

        {/* RIGHT / SMALL SECTION (4 cols): Pipeline & Top Incident */}
        <div className="lg:col-span-4 space-y-6">
          {/* Pipeline Status Flow Card */}
          <Card
            title="Pipeline Status"
            subtitle="Live end-to-end intelligence pipeline"
          >
            <div className="space-y-3">
              {/* Stage 1: LIVE EVENTS */}
              <div className="flex items-center justify-between p-3 rounded-lg bg-[#f9fafb] border border-[#e5e5e5]">
                <div className="flex items-center gap-2.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse-subtle" />
                  <div>
                    <span className="text-xs font-semibold text-[#171717] block">
                      LIVE EVENTS
                    </span>
                    <span className="text-[11px] text-[#737373]">
                      SIEM • Space • Sensors
                    </span>
                  </div>
                </div>
                <span className="font-mono text-xs font-semibold text-[#171717]">
                  {eventsPerSec} / sec
                </span>
              </div>

              <div className="flex justify-center -my-1 text-[#a3a3a3] text-xs">↓</div>

              {/* Stage 2: PROCESSING */}
              <div className="flex items-center justify-between p-3 rounded-lg bg-[#f9fafb] border border-[#e5e5e5]">
                <div className="flex items-center gap-2.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-blue-600" />
                  <div>
                    <span className="text-xs font-semibold text-[#171717] block">
                      PROCESSING & CORRELATION
                    </span>
                    <span className="text-[11px] text-[#737373]">
                      ML Behavioral Detection
                    </span>
                  </div>
                </div>
                <span className="font-mono text-xs text-blue-700 font-medium">
                  {processingLatencyMs}ms
                </span>
              </div>

              <div className="flex justify-center -my-1 text-[#a3a3a3] text-xs">↓</div>

              {/* Stage 3: MITRE */}
              <div className="flex items-center justify-between p-3 rounded-lg bg-[#f9fafb] border border-[#e5e5e5]">
                <div className="flex items-center gap-2.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-blue-600" />
                  <div>
                    <span className="text-xs font-semibold text-[#171717] block">
                      MITRE ATT&CK
                    </span>
                    <span className="text-[11px] text-[#737373]">
                      Technique Enrichment v14.1
                    </span>
                  </div>
                </div>
                <span className="text-[11px] text-emerald-700 font-medium bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-200">
                  Synced
                </span>
              </div>

              <div className="flex justify-center -my-1 text-[#a3a3a3] text-xs">↓</div>

              {/* Stage 4: PRIORITY */}
              <div className="flex items-center justify-between p-3 rounded-lg bg-[#f9fafb] border border-[#e5e5e5]">
                <div className="flex items-center gap-2.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-blue-600" />
                  <div>
                    <span className="text-xs font-semibold text-[#171717] block">
                      SENTINEL-X PRIORITY
                    </span>
                    <span className="text-[11px] text-[#737373]">
                      Explainable Risk Attribution
                    </span>
                  </div>
                </div>
                <span className="text-[11px] text-blue-700 font-medium bg-blue-50 px-2 py-0.5 rounded-full border border-blue-200">
                  Active
                </span>
              </div>
            </div>
          </Card>

          {/* Current Top Incident Highlight */}
          {topIncident && (
            <Card
              title="Top Active Incident"
              subtitle="Highest assessed risk incident"
              headerAction={
                <SeverityBadge severity={topIncident.priority} size="sm" variant="sentinel" />
              }
            >
              <div className="space-y-3 text-xs">
                <div>
                  <div className="font-semibold text-sm text-[#171717]">
                    {topIncident.title}
                  </div>
                  <div className="flex items-center gap-2 mt-1 text-[#737373]">
                    <span className="font-mono font-medium text-[#171717]">{topIncident.incidentId}</span>
                    <span>•</span>
                    <span>Asset: <strong className="text-[#171717]">{topIncident.affectedAsset}</strong></span>
                  </div>
                </div>

                <p className="text-[#737373] text-xs line-clamp-3 leading-relaxed">
                  {topIncident.blufSummary}
                </p>

                <div className="pt-2 border-t border-[#e5e5e5] flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <span className="text-[11px] text-[#737373]">Risk Score:</span>
                    <span className="font-mono font-bold text-base text-[#171717]">
                      {topIncident.riskScore}
                    </span>
                    <span className="text-[10px] text-[#737373]">/ 100</span>
                  </div>
                  <button
                    onClick={() => handleIncidentClick(topIncident.incidentId)}
                    className="px-3 py-1.5 rounded-lg bg-[#000000] text-white hover:bg-neutral-800 text-xs font-medium flex items-center gap-1 cursor-pointer transition-colors"
                  >
                    Investigate <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </Card>
          )}
        </div>
      </div>

      {/* Alert Detail Drawer when clicking an alert */}
      <DrawerPanel
        isOpen={!!selectedAlert}
        onClose={() => setSelectedAlert(null)}
        title={selectedAlert?.title || selectedAlert?.eventType || 'Alert Detail'}
        subtitle={`Alert ID: ${selectedAlert?.alertId} • Observed on ${selectedAlert?.asset || selectedAlert?.sourceName}`}
      >
        {selectedAlert && (
          <div className="space-y-6 text-xs">
            {/* Meta Row: Status, Priority, Confidence + Analyst Decision Actions (Feature 3) */}
            <div className="p-3.5 rounded-xl bg-[#f9fafb] border border-[#e5e5e5] space-y-3">
              <div className="grid grid-cols-3 gap-3">
                <div>
                  <span className="text-[11px] text-[#737373] block">Status</span>
                  <span
                    className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold mt-1 border ${
                      selectedAlert.status === 'Confirmed Threat'
                        ? 'bg-rose-50 text-rose-700 border-rose-200'
                        : selectedAlert.status === 'False Positive'
                        ? 'bg-amber-50 text-amber-700 border-amber-200'
                        : selectedAlert.status === 'Investigating'
                        ? 'bg-blue-50 text-blue-700 border-blue-200'
                        : 'bg-neutral-100 text-neutral-800 border-neutral-200'
                    }`}
                  >
                    {selectedAlert.status || 'Investigating'}
                  </span>
                </div>
                <div>
                  <span className="text-[11px] text-[#737373] block">Priority</span>
                  <div className="mt-1">
                    <SeverityBadge severity={selectedAlert.priority || selectedAlert.sourceSeverity} size="sm" variant="sentinel" />
                  </div>
                </div>
                <div>
                  <span className="text-[11px] text-[#737373] block">Detection Confidence</span>
                  <span className="font-mono font-semibold text-[#171717] mt-1 block">
                    {selectedAlert.confidence}%
                  </span>
                </div>
              </div>

              {/* Analyst Decision Actions */}
              <div className="pt-2.5 border-t border-[#e5e5e5]">
                <span className="text-[10px] uppercase font-bold tracking-wider text-[#737373] block mb-2">
                  Analyst Decision Actions
                </span>
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    onClick={() => {
                      updateAlertStatus(selectedAlert.alertId, 'Confirmed Threat');
                      setSelectedAlert({ ...selectedAlert, status: 'Confirmed Threat' });
                    }}
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer ${
                      selectedAlert.status === 'Confirmed Threat'
                        ? 'bg-rose-600 text-white shadow-xs'
                        : 'border border-rose-200 bg-rose-50/80 text-rose-700 hover:bg-rose-100'
                    }`}
                  >
                    <ShieldAlert className="w-3.5 h-3.5" />
                    Confirm Threat
                  </button>

                  <button
                    onClick={() => {
                      updateAlertStatus(selectedAlert.alertId, 'False Positive');
                      setSelectedAlert({ ...selectedAlert, status: 'False Positive' });
                    }}
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer ${
                      selectedAlert.status === 'False Positive'
                        ? 'bg-amber-600 text-white shadow-xs'
                        : 'border border-amber-200 bg-amber-50/80 text-amber-700 hover:bg-amber-100'
                    }`}
                  >
                    <AlertTriangle className="w-3.5 h-3.5" />
                    False Positive
                  </button>

                  <button
                    onClick={() => {
                      updateAlertStatus(selectedAlert.alertId, 'Investigating');
                      setSelectedAlert({ ...selectedAlert, status: 'Investigating' });
                    }}
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer ${
                      selectedAlert.status === 'Investigating'
                        ? 'bg-blue-600 text-white shadow-xs'
                        : 'border border-blue-200 bg-blue-50/80 text-blue-700 hover:bg-blue-100'
                    }`}
                  >
                    <Clock className="w-3.5 h-3.5" />
                    Investigate
                  </button>
                </div>
              </div>
            </div>

            {/* WHAT HAPPENED? */}
            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-[#737373] mb-1.5">
                What Happened?
              </h4>
              <p className="text-sm text-[#171717] bg-white p-3 rounded-lg border border-[#e5e5e5] leading-relaxed">
                {selectedAlert.whatHappened || 'Unusual behavioral telemetry detected on host.'}
              </p>
            </div>

            {/* ATTACK BEHAVIOR */}
            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-[#737373] mb-1.5">
                Attack Behavior
              </h4>
              <div className="flex items-center gap-2 p-2.5 rounded-lg bg-white border border-[#e5e5e5]">
                <span className="font-medium text-[#171717]">
                  {selectedAlert.attackBehavior || 'Command execution'}
                </span>
                {selectedAlert.behavioralMatch && (
                  <span className="text-[11px] text-blue-700 bg-blue-50 px-2 py-0.5 rounded-full border border-blue-200">
                    {selectedAlert.behavioralMatch}
                  </span>
                )}
              </div>
            </div>

            {/* MITRE ATT&CK Enrichment */}
            {selectedAlert.mitreId && (
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-[#737373]">
                    MITRE ATT&CK (Intelligence Enrichment)
                  </h4>
                  <span className="text-[10px] text-[#737373] italic">Enrichment layer</span>
                </div>
                <div className="p-3.5 rounded-lg bg-white border border-[#e5e5e5] space-y-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-xs bg-[#f5f5f5] px-2 py-0.5 rounded border border-[#e5e5e5] text-[#171717]">
                      {selectedAlert.mitreId}
                    </span>
                    <span className="font-semibold text-sm text-[#171717]">
                      {selectedAlert.mitreName}
                    </span>
                    <span className="text-[11px] px-2 py-0.2 rounded-full bg-neutral-100 text-neutral-700">
                      Tactic: {selectedAlert.mitreTactic}
                    </span>
                  </div>
                  <p className="text-xs text-[#737373] leading-relaxed">
                    {selectedAlert.mitreDescription}
                  </p>
                </div>
              </div>
            )}

            {/* WHY WAS THIS PRIORITIZED? */}
            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-[#737373] mb-1.5">
                Why Was This Prioritized?
              </h4>
              <div className="p-3.5 rounded-lg bg-white border border-[#e5e5e5] space-y-2">
                <div className="flex items-center gap-2 text-xs mb-2 pb-2 border-b border-[#e5e5e5]">
                  <span className="text-[#737373]">Source severity:</span>
                  <SeverityBadge severity={selectedAlert.sourceSeverity} size="sm" variant="source" />
                  <span className="text-[#a3a3a3]">→</span>
                  <span className="text-[#737373]">Sentinel-X Priority:</span>
                  <SeverityBadge severity={selectedAlert.priority} size="sm" variant="sentinel" />
                </div>
                {selectedAlert.priorityReason && (
                  <p className="text-xs font-medium text-blue-900 bg-blue-50/70 p-2 rounded-md border border-blue-100">
                    Reason: {selectedAlert.priorityReason}
                  </p>
                )}
                <div className="space-y-1.5 pt-1">
                  {(selectedAlert.whyPrioritized || [
                    '+ Strong behavioral match to attack vector',
                    '+ Multiple related events within temporal proximity',
                    '+ High-confidence ML detection model score',
                  ]).map((factor, idx) => (
                    <div key={idx} className="flex items-center gap-2 text-xs text-[#171717]">
                      <span className="text-blue-600 font-bold">•</span>
                      <span>{factor}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* EVIDENCE TIMELINE */}
            {selectedAlert.evidenceTimeline && selectedAlert.evidenceTimeline.length > 0 && (
              <div>
                <h4 className="text-xs font-semibold uppercase tracking-wider text-[#737373] mb-1.5">
                  Evidence Timeline
                </h4>
                <div className="space-y-2 border-l-2 border-[#e5e5e5] ml-2 pl-3 py-1">
                  {selectedAlert.evidenceTimeline.map((ev, idx) => (
                    <div key={idx} className="relative text-xs">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[11px] font-semibold text-[#171717]">
                          {ev.time}
                        </span>
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#f5f5f5] text-[#737373]">
                          {ev.source}
                        </span>
                      </div>
                      <div className="font-medium text-[#171717] mt-0.5">{ev.event}</div>
                      <div className="text-[11px] text-[#737373]">{ev.detail}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* RECOMMENDED ACTION */}
            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-[#737373] mb-1.5">
                Recommended Action
              </h4>
              <div className="p-3.5 rounded-lg bg-emerald-50/60 border border-emerald-200 text-emerald-900 text-xs font-medium">
                {selectedAlert.recommendedAction || 'Validate activity on affected asset.'}
              </div>
            </div>
          </div>
        )}
      </DrawerPanel>
    </div>
  );
};
