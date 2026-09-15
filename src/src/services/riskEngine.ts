import { RiskFactors, RiskWeights, RiskScore, PriorityLevel } from '../types';

export const defaultWeights: RiskWeights = {
  evidenceStrength: 0.30,
  assetCriticality: 0.25,
  correlationStrength: 0.20,
  threatIntelConfidence: 0.15,
  temporalCorrelation: 0.10,
};

export const riskEngine = {
  calculateScore: (factors: RiskFactors, weights: RiskWeights = defaultWeights): number => {
    const raw =
      factors.evidenceStrength * weights.evidenceStrength +
      factors.assetCriticality * weights.assetCriticality +
      factors.correlationStrength * weights.correlationStrength +
      factors.threatIntelConfidence * weights.threatIntelConfidence +
      factors.temporalCorrelation * weights.temporalCorrelation;
    return Math.round(Math.min(100, Math.max(0, raw)));
  },

  calculatePriority: (score: number): PriorityLevel => {
    if (score >= 85) return 'CRITICAL';
    if (score >= 65) return 'HIGH';
    if (score >= 40) return 'MEDIUM';
    return 'LOW';
  },

  generateExplanation: (factors: RiskFactors, score: number, asset: string): string => {
    if (score >= 85) {
      return `Risk score (${score}/100) is CRITICAL because multiple independent sources corroborate high-impact activity against critical asset [${asset}] within a short temporal window (${factors.temporalCorrelation}%), reinforced by strong threat intelligence corroboration (${factors.threatIntelConfidence}%).`;
    }
    if (score >= 65) {
      return `Risk score (${score}/100) is HIGH due to elevated asset criticality (${factors.assetCriticality}%) and corroborating telemetry across independent domains, though indicator attribution requires further intelligence verification.`;
    }
    if (score >= 40) {
      return `Risk score (${score}/100) is MEDIUM with moderate correlation indicators. Evidence does not immediately suggest lateral spread, but activity exceeds normal baseline.`;
    }
    return `Risk score (${score}/100) is LOW. Isolated event with single weak source report, low asset criticality (${factors.assetCriticality}%), and absent threat intelligence corroboration. Highly consistent with routine discovery activity or false positive.`;
  },

  explainIncidentScore: (incidentId: string, factors: RiskFactors, asset: string, weights: RiskWeights = defaultWeights): RiskScore => {
    const finalScore = riskEngine.calculateScore(factors, weights);
    const explanation = riskEngine.generateExplanation(factors, finalScore, asset);
    return {
      incidentId,
      finalScore,
      factors,
      weights,
      explanation,
    };
  },
};
