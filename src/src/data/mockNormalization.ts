import { CorrelationConfig, BLUFReport, NormalizationRecord } from '../types';

export const defaultCorrelationConfig: CorrelationConfig = {
  windowMinutes: 15,
  minCorroboratingSources: 2,
  rules: [
    {
      ruleId: 'RULE-01',
      label: 'Multi-Source Asset Correlation',
      description: 'Correlate events across different domains affecting identical assets within temporal proximity window',
      enabled: true,
      configurable: true,
    },
    {
      ruleId: 'RULE-02',
      label: 'Credential Access into Execution Chain',
      description: 'Detect brute force / credential dump immediately followed by script execution on the same host',
      enabled: true,
      configurable: true,
    },
    {
      ruleId: 'RULE-03',
      label: 'Telemetry Anomaly Isolation',
      description: 'Prevent raw satellite telemetry anomalies from elevating to confirmed cyber threats without cyber corroboration',
      enabled: true,
      configurable: false,
    },
    {
      ruleId: 'RULE-04',
      label: 'CISA KEV Known Exploit Boost',
      description: 'Automatically prioritize alerts that match actively exploited vulnerabilities in CISA KEV catalog',
      enabled: true,
      configurable: true,
    },
  ],
};

export const overviewTimelineData = [
  { time: '10:00', siem: 820, satellite: 210, sensors: 340 },
  { time: '10:10', siem: 940, satellite: 214, sensors: 360 },
  { time: '10:20', siem: 890, satellite: 218, sensors: 390 },
  { time: '10:30', siem: 1100, satellite: 230, sensors: 410 },
  { time: '10:40', siem: 1248, satellite: 214, sensors: 425 },
  { time: '10:50', siem: 1180, satellite: 212, sensors: 405 },
];

export const priorityDistributionData = [
  { priority: 'CRITICAL', count: 1, color: '#ef4444' },
  { priority: 'HIGH', count: 4, color: '#f97316' },
  { priority: 'MEDIUM', count: 2, color: '#f59e0b' },
  { priority: 'LOW', count: 3, color: '#10b981' },
];

export const mockBLUFReports: BLUFReport[] = [
  {
    reportId: 'BLUF-1042',
    incidentId: 'INC-1042',
    generatedAt: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
    priority: 'HIGH',
    bottomLine:
      'CONFIRMED MULTI-STAGE CYBERATTACK: Adversaries achieved credential compromise and executed encoded PowerShell payloads against core financial host HOST-042.',
    whyItMatters:
      'HOST-042 processes core transactions. Correlated behavioral signatures match CISA KEV documented threat actor playbooks. Outbound C2 communication is actively beaconing.',
    evidenceSummary: [
      '4 brute force authentication attempts targeting svc_database_admin (10:42 UTC)',
      'Direct process handle open to lsass.exe for credential harvesting (10:44 UTC)',
      'Base64-encoded PowerShell command invocation from spoolsv.exe (10:47 UTC)',
      'TCP beaconing to external IP 198.51.100.42 on port 443 (10:49 UTC)',
    ],
    mitreIds: ['T1110', 'T1003.001', 'T1059.001', 'T1071.001'],
    riskScore: 88,
    confidence: 94,
    recommendedActions: [
      'Immediately isolate HOST-042 from the internal network fabric',
      'Revoke Kerberos TGT tickets and rotate credentials for svc_database_admin',
      'Block destination IP 198.51.100.42 across all boundary firewalls',
      'Collect volatile RAM dump from HOST-042 for offline forensic extraction',
    ],
    classificationNote: 'INTERNAL ONLY // TLP:AMBER // SOC DISPATCH',
  },
];

export const mockNormalizationRecords: NormalizationRecord[] = [
  {
    sourceId: 'mordor',
    sourceName: 'OTRF Mordor',
    domain: 'SIEM',
    dataCompleteness: 94,
    adapterName: 'Mordor-Sysmon-JSON-Adapter-v2',
    rawSample: {
      'EventID': '1',
      'Image': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      'CommandLine': 'powershell.exe -NoP -NonI -W Hidden -enc SQBFAFgA...',
      'ParentImage': 'C:\\Windows\\System32\\spoolsv.exe',
      'Computer': 'HOST-042.corp.internal',
      'UtcTime': '2026-09-15 10:47:31.214',
    },
    fields: [
      { sourceField: 'UtcTime', canonicalField: 'timestamp', present: true, value: '2026-09-15T10:47:31.214Z' },
      { sourceField: 'Computer', canonicalField: 'asset', present: true, value: 'HOST-042' },
      { sourceField: 'CommandLine', canonicalField: 'indicator', present: true, value: 'powershell.exe -enc SQBFAFgA...' },
      { sourceField: 'EventID', canonicalField: 'eventType', present: true, value: 'Process Creation (Sysmon 1)' },
    ],
  },
  {
    sourceId: 'nasa_telemanom',
    sourceName: 'NASA JPL Telemetry',
    domain: 'SATELLITE_SPACE',
    dataCompleteness: 82,
    adapterName: 'NASA-Telemanom-CCSDS-Adapter',
    rawSample: {
      'spacecraft': 'SMAP',
      'channel_id': 'THR-MOD-04B',
      'telemetry_val': '82.4',
      'expected_val': '65.0',
      'delta_pct': '+26.8%',
      'timestamp': '1789468514',
    },
    fields: [
      { sourceField: 'timestamp', canonicalField: 'timestamp', present: true, value: '2026-09-15T10:35:14Z' },
      { sourceField: 'spacecraft', canonicalField: 'asset', present: true, value: 'SAT-NOAA-19' },
      { sourceField: 'channel_id', canonicalField: 'indicator', present: true, value: 'channel: THR-MOD-04B' },
      { sourceField: 'delta_pct', canonicalField: 'eventType', present: true, value: 'Thermal Deviation (+26.8%)' },
    ],
  },
];
