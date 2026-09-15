/**
 * mitreService.ts
 * ---------------
 * Calls POST /api/mitre/map on the Python RAG backend.
 * Falls back gracefully to mock data when the backend is unreachable
 * (e.g. during local frontend-only development).
 */

import { MitreMappingResult } from '../types';

const BACKEND_BASE = import.meta.env.VITE_MITRE_API_URL ?? 'http://localhost:8000';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AlertClusterPayload {
  cluster_id: string;
  summary: string;
  alert_titles?: string[];
  indicators?: string[];
  tactic_hint?: string;
}

// ---------------------------------------------------------------------------
// Mock fallback data – used when the backend is unreachable
// ---------------------------------------------------------------------------

const MOCK_RESULTS: MitreMappingResult[] = [
  {
    technique_id: 'T1059.001',
    technique_name: 'Command and Scripting Interpreter: PowerShell',
    tactic: 'Execution',
    confidence_score: 87,
    evidence: [
      'Alert: Suspicious PowerShell Encoded Command',
      'Alert: WMI Lateral Movement Detected',
      'IOC observed: 192.168.12.44',
      'LLM rationale: PowerShell encoding pattern matches encoded-command technique.',
    ],
  },
  {
    technique_id: 'T1110.003',
    technique_name: 'Brute Force: Password Spraying',
    tactic: 'Credential Access',
    confidence_score: 72,
    evidence: [
      'Alert: Failed Login – Multiple Accounts',
      'Alert: Account Lockout Threshold Breached',
      'IOC observed: user:svc_backup, user:admin, user:jdoe',
    ],
  },
  {
    technique_id: 'T1021.001',
    technique_name: 'Remote Services: Remote Desktop Protocol',
    tactic: 'Lateral Movement',
    confidence_score: 55,
    evidence: [
      'Alert: RDP Login from Unusual Source',
      'IOC observed: 10.0.0.55',
    ],
  },
];

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export const mitreService = {
  /**
   * Map a single alert cluster to a MITRE ATT&CK technique.
   * Returns a MitreMappingResult from the backend, or mock data on failure.
   */
  mapCluster: async (payload: AlertClusterPayload): Promise<MitreMappingResult> => {
    try {
      const resp = await fetch(`${BACKEND_BASE}/api/mitre/map`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(15_000),
      });

      if (!resp.ok) {
        const msg = await resp.text();
        throw new Error(`MITRE API ${resp.status}: ${msg}`);
      }

      return (await resp.json()) as MitreMappingResult;
    } catch (err) {
      console.warn('[mitreService] Backend unreachable, using mock data.', err);
      // Return a deterministic mock based on the cluster_id index
      const idx = parseInt(payload.cluster_id.replace(/\D/g, '') || '0', 10) % MOCK_RESULTS.length;
      return MOCK_RESULTS[idx];
    }
  },

  /**
   * Map multiple alert clusters in parallel.
   * Each failed individual call is replaced with a mock result instead of
   * rejecting the entire batch.
   */
  mapClusters: async (
    payloads: AlertClusterPayload[]
  ): Promise<MitreMappingResult[]> => {
    return Promise.all(payloads.map((p) => mitreService.mapCluster(p)));
  },

  /** Health-check the backend. Returns true if reachable. */
  checkHealth: async (): Promise<boolean> => {
    try {
      const resp = await fetch(`${BACKEND_BASE}/api/mitre/health`, {
        signal: AbortSignal.timeout(5_000),
      });
      return resp.ok;
    } catch {
      return false;
    }
  },

  /** Expose mock data so the UI can show a populated view without any backend. */
  getMockResults: (): MitreMappingResult[] => [...MOCK_RESULTS],
};
