import { TelemetryRecord } from '../types';

export const mockTelemetryRecords: TelemetryRecord[] = [
  {
    recordId: 'TEL-001',
    timestamp: new Date(Date.now() - 11 * 60 * 1000).toISOString(),
    sourceId: 'nasa_telemanom',
    sourceName: 'NASA JPL Telemetry',
    spacecraftId: 'SAT-NOAA-19',
    telemetryParameter: 'THR-MOD-04B (Thermal Radiator)',
    observedValue: 82.4,
    expectedValue: 65.0,
    deviation: 26.8,
    anomalyScore: 84,
    location: 'Low Earth Orbit (Inclination 98.7°)',
    operationalStatus: 'DEVIATION',
    isAnomaly: true,
    anomalyClassification: 'TELEMETRY_ANOMALY',
    corroboratedByCyberEvidence: false,
  },
  {
    recordId: 'TEL-002',
    timestamp: new Date(Date.now() - 6 * 60 * 1000).toISOString(),
    sourceId: 'esa_opssat',
    sourceName: 'ESA OPS-SAT',
    spacecraftId: 'OPS-SAT-1',
    telemetryParameter: 'PWR-BUS-V (Main Bus Voltage)',
    observedValue: 28.1,
    expectedValue: 28.0,
    deviation: 0.35,
    anomalyScore: 12,
    location: 'LEO 510km SSO',
    operationalStatus: 'NORMAL',
    isAnomaly: false,
    anomalyClassification: 'NORMAL',
    corroboratedByCyberEvidence: false,
  },
  {
    recordId: 'TEL-003',
    timestamp: new Date(Date.now() - 3 * 60 * 1000).toISOString(),
    sourceId: 'opensky',
    sourceName: 'OpenSky Network',
    aircraftId: 'ICAO-400A21',
    telemetryParameter: 'ALT-GNSS-FT (GPS Barometric Altitude)',
    observedValue: 34000,
    expectedValue: 34000,
    deviation: 0,
    anomalyScore: 4,
    location: 'FIR Sector London/Maastricht',
    operationalStatus: 'NORMAL',
    isAnomaly: false,
    anomalyClassification: 'NORMAL',
    corroboratedByCyberEvidence: false,
  },
];

export const mockTelemetry = mockTelemetryRecords;

export const telemetryTimeSeries = [
  { time: '10:00', value: 64.8, expected: 65.0, deviation: 0.2 },
  { time: '10:10', value: 65.1, expected: 65.0, deviation: 0.1 },
  { time: '10:20', value: 65.5, expected: 65.0, deviation: 0.5 },
  { time: '10:30', value: 71.2, expected: 65.0, deviation: 6.2 },
  { time: '10:35', value: 82.4, expected: 65.0, deviation: 17.4 },
  { time: '10:40', value: 78.9, expected: 65.0, deviation: 13.9 },
  { time: '10:50', value: 69.2, expected: 65.0, deviation: 4.2 },
];

