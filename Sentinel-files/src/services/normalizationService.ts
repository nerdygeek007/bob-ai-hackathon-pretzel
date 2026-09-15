import { NormalizationRecord, SourceType, NormalizedEvent } from '../types';
import { mockNormalizationRecords } from '../data/mockNormalization';

export interface FieldMappingRule {
  sourceField: string;
  canonicalField: string;
  transformation?: string;
}

export const normalizationService = {
  getNormalizationRecords: async (): Promise<NormalizationRecord[]> => {
    return [...mockNormalizationRecords];
  },

  getRecordBySource: async (sourceId: SourceType): Promise<NormalizationRecord | undefined> => {
    return mockNormalizationRecords.find((r) => r.sourceId === sourceId);
  },

  testFieldMapping: async (
    rawPayload: Record<string, string>,
    mappings: FieldMappingRule[]
  ): Promise<Partial<NormalizedEvent>> => {
    const result: Record<string, unknown> = {};
    mappings.forEach((m) => {
      if (rawPayload[m.sourceField] !== undefined) {
        result[m.canonicalField] = rawPayload[m.sourceField];
      }
    });
    return result as Partial<NormalizedEvent>;
  },
};
