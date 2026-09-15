import { Alert, DomainType, SourceType } from '../types';
import { mockAlerts } from '../data/mockAlerts';

export interface IngestionFilter {
  domain?: DomainType;
  sourceId?: SourceType;
  asset?: string;
  limit?: number;
}

export interface IngestionStatusResponse {
  totalIngested: number;
  activeRate: number; // events/sec
  lastCycleTimestamp: string;
}

export const ingestionService = {
  getLiveAlerts: async (filter?: IngestionFilter): Promise<Alert[]> => {
    // Simulated async fetch with optional filter
    let results = [...mockAlerts];
    if (filter?.domain) {
      results = results.filter((a) => a.domain === filter.domain);
    }
    if (filter?.sourceId) {
      results = results.filter((a) => a.sourceId === filter.sourceId);
    }
    if (filter?.asset) {
      results = results.filter((a) => a.asset?.toLowerCase().includes(filter.asset!.toLowerCase()));
    }
    if (filter?.limit) {
      results = results.slice(0, filter.limit);
    }
    return results;
  },

  getIngestionStatus: async (): Promise<IngestionStatusResponse> => {
    return {
      totalIngested: 53054,
      activeRate: 48.2,
      lastCycleTimestamp: new Date().toISOString(),
    };
  },

  testConnection: async (sourceId: string): Promise<{ success: boolean; latencyMs: number; message: string }> => {
    await new Promise((res) => setTimeout(res, 400));
    return {
      success: true,
      latencyMs: Math.floor(Math.random() * 30) + 15,
      message: `Connection established to ${sourceId}. Adapter handshake verified.`,
    };
  },
};
