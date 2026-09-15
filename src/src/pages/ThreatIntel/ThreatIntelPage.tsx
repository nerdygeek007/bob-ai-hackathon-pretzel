import React, { useState } from 'react';
import { mockThreatIndicators, mockCISAKEV } from '../../data/mockThreatIntel';
import { Card } from '../../components/ui/Card';
import { DrawerPanel } from '../../components/ui/DrawerPanel';
import { ThreatIndicator, CISAKEVEntry } from '../../types';
import { Globe2, ShieldAlert, AlertCircle, Search, Filter, Layers, Database } from 'lucide-react';

export const ThreatIntelPage: React.FC = () => {
  const [selectedIndicator, setSelectedIndicator] = useState<ThreatIndicator | null>(null);
  const [selectedKev, setSelectedKev] = useState<CISAKEVEntry | null>(null);
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const filteredIndicators = mockThreatIndicators.filter((i) => {
    if (typeFilter !== 'ALL' && i.type !== typeFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      if (!i.value.toLowerCase().includes(q) && !i.source.toLowerCase().includes(q)) return false;
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono text-slate-100 uppercase tracking-wide">
            THREAT INTELLIGENCE & VULNERABILITY ENRICHMENT
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Contextual threat indicators and CISA Known Exploited Vulnerabilities (KEV)
          </p>
        </div>

        {/* Search & Filter */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search IOC, CVE, Actor..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-slate-900 border border-slate-700 text-slate-200 text-xs font-mono rounded pl-8 pr-3 py-1.5 focus:outline-none focus:border-cyan-500 w-52"
            />
          </div>

          <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 p-1 rounded font-mono text-xs">
            {['ALL', 'IP', 'HASH', 'CVE', 'ACTOR', 'CAMPAIGN'].map((t) => (
              <button
                key={t}
                onClick={() => setTypeFilter(t)}
                className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                  typeFilter === t
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-700'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {t}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* SECTION 23: CISA KEV ENRICHMENT HIGHLIGHT PANEL */}
      <Card
        title="CISA Known Exploited Vulnerabilities (KEV) Catalog Enrichment"
        subtitle="Vulnerability match on active assets provides contextual risk evidence"
        badge={
          <span className="text-[10px] px-2 py-0.2 rounded font-mono font-bold bg-red-950 text-red-400 border border-red-800">
            {mockCISAKEV.length} Matched in Telemetry
          </span>
        }
      >
        <div className="space-y-3 font-mono text-xs">
          <div className="p-2.5 bg-amber-950/20 border border-amber-900/40 rounded text-slate-300 text-xs">
            ⚠️ <strong>KEV Risk Rule:</strong> A match in CISA KEV confirms that this CVE is actively
            exploited in the wild. However, Sentinel-X does NOT automatically classify every KEV match
            as CRITICAL without corroborating execution evidence.
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {mockCISAKEV.map((kev) => (
              <div
                key={kev.cveId}
                onClick={() => setSelectedKev(kev)}
                className="p-4 bg-slate-900/80 border border-red-900/50 hover:border-red-500 rounded cursor-pointer transition-all shadow-sm"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <span className="text-base font-black text-red-400">{kev.cveId}</span>
                    <span className="text-xs text-slate-300 font-semibold block mt-0.5">
                      {kev.vendor} — {kev.product}
                    </span>
                  </div>
                  <span className="text-[10px] px-2 py-0.5 rounded font-bold bg-red-950 text-red-300 border border-red-800">
                    KNOWN EXPLOITED
                  </span>
                </div>

                <p className="text-[11px] text-slate-400 mt-2 line-clamp-2">
                  {kev.vulnerabilityName}
                </p>

                <div className="mt-3 pt-2 border-t border-slate-800 flex items-center justify-between text-[11px]">
                  <span className="text-slate-400">
                    Matched Asset: <strong className="text-cyan-300">{kev.relatedAssets.join(', ')}</strong>
                  </span>
                  <span className="text-amber-400 font-bold">
                    Incident: {kev.relatedIncidentIds.join(', ')}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </Card>

      {/* SECTION 24: THREAT INDICATORS TABLE */}
      <Card
        title="Observed Threat Intelligence Indicators (CTI Feed)"
        subtitle="Corroborating indicators linked to observed events"
        noPadding
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="border-b border-[#1f293d] bg-slate-900/70 text-slate-400 text-[11px] uppercase tracking-wider font-semibold">
                <th className="py-3 px-4">Indicator Value</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Intelligence Source</th>
                <th className="py-3 px-4">Reputation</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4">First Seen</th>
                <th className="py-3 px-4">Related Incidents</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e293b]/60">
              {filteredIndicators.map((ioc) => (
                <tr
                  key={ioc.indicatorId}
                  onClick={() => setSelectedIndicator(ioc)}
                  className="hover:bg-slate-800/50 transition-colors cursor-pointer"
                >
                  <td className="py-3 px-4 font-bold text-cyan-300 max-w-xs truncate">
                    {ioc.value}
                  </td>
                  <td className="py-3 px-4">
                    <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700 font-semibold">
                      {ioc.type}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-slate-400">{ioc.source}</td>
                  <td className="py-3 px-4">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        ioc.reputation === 'MALICIOUS'
                          ? 'bg-red-950 text-red-400 border-red-800'
                          : ioc.reputation === 'SUSPICIOUS'
                          ? 'bg-amber-950 text-amber-400 border-amber-800'
                          : 'bg-slate-800 text-slate-400 border-slate-700'
                      }`}
                    >
                      {ioc.reputation}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-bold text-slate-200">{ioc.confidence}%</td>
                  <td className="py-3 px-4 text-slate-400">
                    {new Date(ioc.firstSeen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </td>
                  <td className="py-3 px-4">
                    {ioc.relatedIncidentIds.length > 0 ? (
                      <span className="font-bold text-cyan-400">
                        {ioc.relatedIncidentIds.join(', ')}
                      </span>
                    ) : (
                      <span className="text-slate-500">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Indicator Detail Drawer */}
      <DrawerPanel
        isOpen={!!selectedIndicator}
        onClose={() => setSelectedIndicator(null)}
        title={selectedIndicator ? `CTI Indicator: ${selectedIndicator.indicatorId}` : ''}
        subtitle={selectedIndicator?.type}
      >
        {selectedIndicator && (
          <div className="space-y-4 font-mono text-xs">
            <div className="p-3 bg-slate-900 border border-slate-800 rounded">
              <span className="text-slate-400 text-[10px] uppercase block mb-1">Indicator Value</span>
              <code className="text-cyan-300 text-xs break-all block bg-slate-950 p-2 rounded border border-slate-800">
                {selectedIndicator.value}
              </code>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 bg-slate-900/60 border border-slate-800 rounded">
                <span className="text-slate-400 text-[10px] uppercase">Reputation</span>
                <span className="text-red-400 font-bold text-sm block mt-0.5">
                  {selectedIndicator.reputation}
                </span>
              </div>
              <div className="p-3 bg-slate-900/60 border border-slate-800 rounded">
                <span className="text-slate-400 text-[10px] uppercase">Source Feed</span>
                <span className="text-slate-200 font-semibold block mt-0.5">
                  {selectedIndicator.source}
                </span>
              </div>
            </div>

            <div className="p-3 bg-slate-900 border border-slate-800 rounded">
              <span className="text-slate-400 text-[10px] uppercase block mb-1.5">CTI Tags</span>
              <div className="flex flex-wrap gap-1">
                {selectedIndicator.tags.map((tag) => (
                  <span
                    key={tag}
                    className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[11px]"
                  >
                    #{tag}
                  </span>
                ))}
              </div>
            </div>
          </div>
        )}
      </DrawerPanel>
    </div>
  );
};
