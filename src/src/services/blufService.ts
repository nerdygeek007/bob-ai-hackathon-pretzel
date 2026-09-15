import { BLUFReport } from '../types';
import { mockBLUFReports } from '../data/mockNormalization';

export const blufService = {
  getReportByIncidentId: async (incidentId: string): Promise<BLUFReport | undefined> => {
    return mockBLUFReports.find((r) => r.incidentId === incidentId);
  },

  getAllReports: async (): Promise<BLUFReport[]> => {
    return [...mockBLUFReports];
  },

  regenerateReport: async (incidentId: string): Promise<BLUFReport> => {
    await new Promise((res) => setTimeout(res, 500));
    const existing = mockBLUFReports.find((r) => r.incidentId === incidentId) || mockBLUFReports[0];
    return {
      ...existing,
      generatedAt: new Date().toISOString(),
    };
  },
};
