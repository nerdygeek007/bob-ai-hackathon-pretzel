import { MitreTechnique, ThreatIndicator, CISAKEVEntry } from '../types';
import { mockMitreTechniques } from '../data/mockMitre';
import { mockThreatIndicators, mockCISAKEV } from '../data/mockThreatIntel';

export const enrichmentService = {
  getRelevantMitreTechniques: async (incidentId?: string): Promise<MitreTechnique[]> => {
    if (!incidentId) return [...mockMitreTechniques];
    return mockMitreTechniques.filter((t) => t.relatedIncidentIds.includes(incidentId));
  },

  getTechniqueById: async (techniqueId: string): Promise<MitreTechnique | undefined> => {
    return mockMitreTechniques.find((t) => t.techniqueId === techniqueId);
  },

  getThreatIndicators: async (): Promise<ThreatIndicator[]> => {
    return [...mockThreatIndicators];
  },

  getCISAKEVEntries: async (): Promise<CISAKEVEntry[]> => {
    return [...mockCISAKEV];
  },

  lookupIndicator: async (val: string): Promise<ThreatIndicator | undefined> => {
    return mockThreatIndicators.find((i) => i.value.toLowerCase() === val.toLowerCase());
  },
};
