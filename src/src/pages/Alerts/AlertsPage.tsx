import React, { useState } from 'react';
import { useSentinel } from '../../store/sentinelStore';
import { Card } from '../../components/ui/Card';
import { SeverityBadge } from '../../components/ui/SeverityBadge';
import { MissingField } from '../../components/ui/MissingField';
import { DrawerPanel } from '../../components/ui/DrawerPanel';
import { Alert, DomainType } from '../../types';
import { Filter, Search, FileCode, CheckCircle, Clock } from 'lucide-react';

export const AlertsPage: React.FC = () => {
  const { alerts, domains } = useSentinel();
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [domainFilter, setDomainFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Check if a source is currently enabled
  const isSourceActive = (domain: DomainType, sourceId: string) => {
    const dom = domains.find((d) => d.id === domain);
    if (!dom || !dom.enabled) return false;
    const src = dom.sources.find((s) => s.id === sourceId);
    return src ? src.enabled : false;
  };

  const filteredAlerts = alerts.filter((alert) => {
    if (domainFilter !== 'ALL' && alert.domain !== domainFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchAsset = alert.asset?.toLowerCase().includes(q);
      const matchIndicator = alert.indicator?.toLowerCase().includes(q);
      const matchEvent = alert.eventType?.toLowerCase().includes(q);
      const matchId = alert.alertId.toLowerCase().includes(q);
      if (!matchAsset && !matchIndicator && !matchEvent && !matchId) return false;
    }
    return true;
  });

  return (
    <div className="space-y-5">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono text-slate-100 uppercase tracking-wide">
            LIVE INGESTION ALERTS
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Normalized sparse telemetry events across primary domains with raw provenance
          </p>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search asset, indicator, ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-slate-900 border border-slate-700 text-slate-200 text-xs font-mono rounded pl-8 pr-3 py-1.5 focus:outline-none focus:border-cyan-500 w-56"
            />
          </div>

          <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 p-1 rounded font-mono text-xs">
            <Filter className="w-3.5 h-3.5 text-slate-400 ml-1.5 mr-1" />
            {['ALL', 'SIEM', 'SATELLITE_SPACE', 'SENSORS'].map((dom) => (
              <button
                key={dom}
                onClick={() => setDomainFilter(dom)}
                className={`px-2.5 py-1 rounded text-[11px] font-semibold transition-colors ${
                  domainFilter === dom
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-700'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {dom === 'ALL' ? 'ALL DOMAINS' : dom.replace('_', ' / ')}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Sparse Data Callout */}
      <div className="bg-slate-900/80 border border-slate-800 rounded p-3 text-xs font-mono text-slate-400 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
          <span>
            <strong className="text-slate-200">Sparse Model Notice:</strong> Missing fields are shown as{' '}
            <span className="text-slate-400 font-bold">— Not provided</span>. Data is never fabricated.
          </span>
        </div>
        <span className="text-[11px] text-slate-400">
          Showing {filteredAlerts.length} events
        </span>
      </div>

      {/* Alerts Table */}
      <Card noPadding>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="border-b border-[#1f293d] bg-slate-900/70 text-slate-400 text-[11px] uppercase tracking-wider font-semibold">
                <th className="py-3 px-3.5">Alert ID</th>
                <th className="py-3 px-3.5">Timestamp</th>
                <th className="py-3 px-3.5">Domain</th>
                <th className="py-3 px-3.5">Source</th>
                <th className="py-3 px-3.5">Asset</th>
                <th className="py-3 px-3.5">Indicator</th>
                <th className="py-3 px-3.5">Event Type</th>
                <th className="py-3 px-3.5">Source Severity</th>
                <th className="py-3 px-3.5">Confidence</th>
                <th className="py-3 px-3.5">Correlation</th>
                <th className="py-3 px-3.5 text-right">Raw Evidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e293b]/60">
              {filteredAlerts.map((alert) => {
                const active = isSourceActive(alert.domain, alert.sourceId);
                return (
                  <tr
                    key={alert.alertId}
                    className={`hover:bg-slate-800/50 transition-colors ${
                      !active ? 'opacity-50' : ''
                    }`}
                  >
                    <td className="py-3 px-3.5 font-bold text-cyan-400">
                      {alert.alertId}
                    </td>
                    <td className="py-3 px-3.5 text-slate-400 whitespace-nowrap">
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3 text-slate-400" />
                        {new Date(alert.timestamp).toLocaleTimeString([], {
                          hour: '2-digit',
                          minute: '2-digit',
                          second: '2-digit',
                        })}
                      </span>
                    </td>
                    <td className="py-3 px-3.5">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${
                          alert.domain === 'SIEM'
                            ? 'bg-sky-950/60 text-sky-400 border-sky-800/60'
                            : alert.domain === 'SATELLITE_SPACE'
                            ? 'bg-purple-950/60 text-purple-400 border-purple-800/60'
                            : 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60'
                        }`}
                      >
                        {alert.domain.replace('_', ' / ')}
                      </span>
                    </td>
                    <td className="py-3 px-3.5 font-semibold text-slate-300">
                      {alert.sourceName}
                    </td>
                    <td className="py-3 px-3.5">
                      {alert.asset ? (
                        <span className="font-semibold text-slate-100">{alert.asset}</span>
                      ) : (
                        <MissingField />
                      )}
                    </td>
                    <td className="py-3 px-3.5">
                      {alert.indicator ? (
                        <span className="text-cyan-300 font-mono">{alert.indicator}</span>
                      ) : (
                        <MissingField />
                      )}
                    </td>
                    <td className="py-3 px-3.5 text-slate-200">
                      {alert.eventType ? alert.eventType : <MissingField />}
                    </td>
                    <td className="py-3 px-3.5">
                      <SeverityBadge severity={alert.sourceSeverity} size="sm" variant="source" />
                    </td>
                    <td className="py-3 px-3.5">
                      {alert.confidence !== undefined ? (
                        <span className="text-slate-200 font-bold">{alert.confidence}%</span>
                      ) : (
                        <MissingField />
                      )}
                    </td>
                    <td className="py-3 px-3.5">
                      {alert.correlationStatus === 'CORRELATED' ? (
                        <span className="inline-flex items-center gap-1 text-[11px] font-bold text-cyan-400">
                          <CheckCircle className="w-3 h-3 text-cyan-400" />
                          {alert.relatedIncidentId || 'Correlated'}
                        </span>
                      ) : (
                        <span className="text-slate-500 text-[11px]">
                          {alert.correlationStatus}
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-3.5 text-right">
                      <button
                        onClick={() => setSelectedAlert(alert)}
                        className="px-2.5 py-1 text-[11px] rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-cyan-300 border border-slate-700 inline-flex items-center gap-1 transition-colors cursor-pointer"
                      >
                        <FileCode className="w-3 h-3 text-cyan-400" />
                        Inspect
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Raw Evidence Drawer */}
      <DrawerPanel
        isOpen={!!selectedAlert}
        onClose={() => setSelectedAlert(null)}
        title={selectedAlert ? `Raw Evidence: ${selectedAlert.alertId}` : ''}
        subtitle={selectedAlert?.rawReference}
      >
        {selectedAlert && (
          <div className="space-y-4 font-mono text-xs">
            <div className="p-3 bg-slate-900 border border-slate-800 rounded">
              <span className="text-[11px] text-slate-400 uppercase tracking-wider block mb-1">
                Data Provenance Reference
              </span>
              <code className="text-cyan-400 text-xs break-all block bg-slate-950 p-2 rounded border border-slate-800">
                {selectedAlert.rawReference}
              </code>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 bg-slate-900/60 border border-slate-800 rounded">
                <span className="text-slate-400 block text-[10px] uppercase">Domain</span>
                <span className="text-slate-100 font-bold mt-0.5 block">{selectedAlert.domain}</span>
              </div>
              <div className="p-3 bg-slate-900/60 border border-slate-800 rounded">
                <span className="text-slate-400 block text-[10px] uppercase">Source Adapter</span>
                <span className="text-slate-100 font-bold mt-0.5 block">{selectedAlert.sourceName}</span>
              </div>
              <div className="p-3 bg-slate-900/60 border border-slate-800 rounded">
                <span className="text-slate-400 block text-[10px] uppercase">Source Reported Severity</span>
                <div className="mt-1">
                  <SeverityBadge severity={selectedAlert.sourceSeverity} size="sm" variant="source" />
                </div>
              </div>
              <div className="p-3 bg-slate-900/60 border border-slate-800 rounded">
                <span className="text-slate-400 block text-[10px] uppercase">Confidence</span>
                <span className="text-cyan-400 font-bold mt-0.5 block">
                  {selectedAlert.confidence !== undefined ? `${selectedAlert.confidence}%` : 'Not provided'}
                </span>
              </div>
            </div>

            <div className="p-3 bg-slate-900 border border-slate-800 rounded">
              <span className="text-[11px] text-slate-400 uppercase tracking-wider block mb-2">
                Simulated Source Raw Payload
              </span>
              <pre className="p-3 bg-slate-950 text-slate-300 rounded border border-slate-800 text-[11px] overflow-x-auto">
{JSON.stringify(
  {
    alert_id: selectedAlert.alertId,
    timestamp: selectedAlert.timestamp,
    raw_source: selectedAlert.sourceName,
    domain_origin: selectedAlert.domain,
    extracted_fields: {
      asset: selectedAlert.asset || null,
      indicator: selectedAlert.indicator || null,
      event_type: selectedAlert.eventType || null,
      source_severity: selectedAlert.sourceSeverity || null,
      confidence: selectedAlert.confidence || null,
    },
    provenance_uri: selectedAlert.rawReference,
  },
  null,
  2
)}
              </pre>
            </div>

            <div className="p-3 bg-cyan-950/30 border border-cyan-900/50 rounded text-cyan-300 text-xs">
              <strong>Sentinel-X Pipeline Note:</strong> Large raw payloads are referenced by URI
              rather than duplicated across the correlation pipeline. Only sparse extracted fields
              participate in active correlation.
            </div>
          </div>
        )}
      </DrawerPanel>
    </div>
  );
};
