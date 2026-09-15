import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { SentinelProvider } from './store/sentinelStore';
import { Sidebar } from './components/Navigation/Sidebar';
import { OverviewPage } from './pages/Overview/OverviewPage';
import { AlertsPage } from './pages/Alerts/AlertsPage';
import { IncidentsPage } from './pages/Incidents/IncidentsPage';
import { IncidentDetailPage } from './pages/Incidents/IncidentDetailPage';
import { DataSourcesPage } from './pages/DataSources/DataSourcesPage';
import { NormalizationPage } from './pages/Normalization/NormalizationPage';
import { CorrelationPage } from './pages/Correlation/CorrelationPage';
import { RiskPage } from './pages/Risk/RiskPage';
import { BLUFPage } from './pages/BLUF/BLUFPage';
import { ThreatIntelPage } from './pages/ThreatIntel/ThreatIntelPage';
import { MitrePage } from './pages/Mitre/MitrePage';
import { TelemetryPage } from './pages/Telemetry/TelemetryPage';
import { SystemHealthPage } from './pages/SystemHealth/SystemHealthPage';
import { SettingsPage } from './pages/Settings/SettingsPage';

export function App() {
  return (
    <SentinelProvider>
      <BrowserRouter>
        <div className="flex h-screen w-screen overflow-hidden bg-[#0b0f17] text-slate-200">
          {/* Left Navigation Sidebar */}
          <Sidebar />

          {/* Main Command Workspace */}
          <main className="flex-1 overflow-y-auto p-6">
            <div className="max-w-[1600px] mx-auto">
              <Routes>
                <Route path="/" element={<OverviewPage />} />
                <Route path="/alerts" element={<AlertsPage />} />
                <Route path="/incidents" element={<IncidentsPage />} />
                <Route path="/incidents/:id" element={<IncidentDetailPage />} />
                <Route path="/sources" element={<DataSourcesPage />} />
                <Route path="/normalization" element={<NormalizationPage />} />
                <Route path="/correlation" element={<CorrelationPage />} />
                <Route path="/risk" element={<RiskPage />} />
                <Route path="/bluf" element={<BLUFPage />} />
                <Route path="/threat-intel" element={<ThreatIntelPage />} />
                <Route path="/mitre" element={<MitrePage />} />
                <Route path="/telemetry" element={<TelemetryPage />} />
                <Route path="/health" element={<SystemHealthPage />} />
                <Route path="/settings" element={<SettingsPage />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </div>
          </main>
        </div>
      </BrowserRouter>
    </SentinelProvider>
  );
}

export default App;
