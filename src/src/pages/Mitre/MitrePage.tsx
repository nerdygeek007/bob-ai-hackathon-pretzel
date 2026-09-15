import React, { useState } from 'react';
import { mockMitreTechniques } from '../../data/mockMitre';
import { Card } from '../../components/ui/Card';
import { DrawerPanel } from '../../components/ui/DrawerPanel';
import { MitreTechnique } from '../../types';
import { Crosshair, ExternalLink, ShieldAlert, Cpu, Layers } from 'lucide-react';

export const MitrePage: React.FC = () => {
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechnique | null>(null);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold font-mono text-slate-100 uppercase tracking-wide">
          MITRE ATT&CK CONTEXTUAL ENRICHMENT
        </h1>
        <p className="text-xs text-slate-400 mt-1 font-mono">
          Filtered matrix of adversary behaviors observed in active incidents (not the full ATT&CK corpus)
        </p>
      </div>

      {/* MITRE Scope Notice */}
      <div className="bg-slate-900/80 border border-slate-800 rounded p-3 text-xs font-mono text-slate-400 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Crosshair className="w-4 h-4 text-cyan-400" />
          <span>
            <strong className="text-slate-200">Focused Contextual Scope:</strong> Displaying only the{' '}
            <span className="text-cyan-400 font-bold">{mockMitreTechniques.length} techniques</span> mapped
            to observed telemetry.
          </span>
        </div>
        <span className="text-[11px] text-slate-400">Enterprise Matrix v14.1</span>
      </div>

      {/* Techniques Table */}
      <Card noPadding>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="border-b border-[#1f293d] bg-slate-900/70 text-slate-400 text-[11px] uppercase tracking-wider font-semibold">
                <th className="py-3 px-4">Technique ID</th>
                <th className="py-3 px-4">Technique Name</th>
                <th className="py-3 px-4">Tactic</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4">Corroborating Evidence</th>
                <th className="py-3 px-4">Related Alerts</th>
                <th className="py-3 px-4">Incidents</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e293b]/60">
              {mockMitreTechniques.map((tech) => (
                <tr
                  key={tech.techniqueId}
                  onClick={() => setSelectedTechnique(tech)}
                  className="hover:bg-slate-800/50 transition-colors cursor-pointer"
                >
                  <td className="py-3 px-4 font-bold text-cyan-400">
                    <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                      {tech.techniqueId}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-slate-100 font-semibold">
                    {tech.techniqueName}
                    {tech.subTechniqueName && (
                      <span className="text-slate-400 block text-[11px] font-normal">
                        : {tech.subTechniqueName}
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-4">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300 border border-slate-700">
                      {tech.tactic}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-bold text-slate-200">
                    {tech.confidence}%
                  </td>
                  <td className="py-3 px-4 text-slate-300">
                    <div className="flex flex-wrap gap-1">
                      {tech.evidenceSources.map((s, idx) => (
                        <span
                          key={idx}
                          className="px-1.5 py-0.2 rounded text-[10px] bg-slate-900 text-slate-400 border border-slate-800"
                        >
                          {s}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="py-3 px-4 text-cyan-400">
                    {tech.relatedAlertIds.join(', ') || '—'}
                  </td>
                  <td className="py-3 px-4">
                    {tech.relatedIncidentIds.length > 0 ? (
                      <span className="font-bold text-amber-400">
                        {tech.relatedIncidentIds.join(', ')}
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

      {/* Technique Drilldown Drawer */}
      <DrawerPanel
        isOpen={!!selectedTechnique}
        onClose={() => setSelectedTechnique(null)}
        title={selectedTechnique ? `${selectedTechnique.techniqueId}: ${selectedTechnique.techniqueName}` : ''}
        subtitle={selectedTechnique?.tactic}
      >
        {selectedTechnique && (
          <div className="space-y-4 font-mono text-xs">
            <div className="p-3 bg-slate-900 border border-slate-800 rounded space-y-1">
              <span className="text-slate-400 text-[10px] uppercase">Description</span>
              <p className="text-slate-200 leading-relaxed text-xs">
                {selectedTechnique.description}
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 bg-slate-900/60 border border-slate-800 rounded">
                <span className="text-slate-400 text-[10px] uppercase">Attribution Confidence</span>
                <span className="text-cyan-400 font-bold text-base block mt-0.5">
                  {selectedTechnique.confidence}%
                </span>
              </div>
              <div className="p-3 bg-slate-900/60 border border-slate-800 rounded">
                <span className="text-slate-400 text-[10px] uppercase">Associated Tactic</span>
                <span className="text-slate-200 font-bold block mt-0.5">
                  {selectedTechnique.tactic}
                </span>
              </div>
            </div>

            {selectedTechnique.threatActors && selectedTechnique.threatActors.length > 0 && (
              <div className="p-3 bg-slate-900 border border-slate-800 rounded">
                <span className="text-slate-400 text-[10px] uppercase block mb-1.5">
                  Associated Threat Groups
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {selectedTechnique.threatActors.map((actor) => (
                    <span
                      key={actor}
                      className="px-2 py-0.5 rounded bg-red-950/60 text-red-300 border border-red-800 text-xs font-bold"
                    >
                      {actor}
                    </span>
                  ))}
                </div>
              </div>
            )}

            <div className="p-3 bg-slate-900 border border-slate-800 rounded">
              <span className="text-slate-400 text-[10px] uppercase block mb-1">
                Corroborating Evidence Sources
              </span>
              <ul className="list-disc list-inside text-slate-300 space-y-0.5">
                {selectedTechnique.evidenceSources.map((ev, idx) => (
                  <li key={idx}>{ev}</li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </DrawerPanel>
    </div>
  );
};
