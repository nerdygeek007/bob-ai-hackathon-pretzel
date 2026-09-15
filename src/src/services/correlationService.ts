import { Incident, CorrelationConfig } from '../types';
import { mockIncidents } from '../data/mockIncidents';
import { defaultCorrelationConfig } from '../data/mockNormalization';

export const correlationService = {
  getCorrelatedIncidents: async (): Promise<Incident[]> => {
    return [...mockIncidents];
  },

  getIncidentById: async (id: string): Promise<Incident | undefined> => {
    return mockIncidents.find((inc) => inc.incidentId === id);
  },

  getCorrelationConfig: async (): Promise<CorrelationConfig> => {
    return { ...defaultCorrelationConfig };
  },

  runCorrelationPass: async (_config: CorrelationConfig): Promise<{ newCorrelations: number; updatedIncidents: number }> => {
    // Simulated correlation execution cycle
    await new Promise((res) => setTimeout(res, 350));
    return {
      newCorrelations: 0,
      updatedIncidents: 3,
    };
  },
};
