import React, { useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { SentinelProvider } from './store/sentinelStore';
import { Sidebar } from './components/Navigation/Sidebar';
import { Header } from './components/Navigation/Header';
import { OverviewPage } from './pages/Overview/OverviewPage';
import { AlertsPage } from './pages/Alerts/AlertsPage';
import { IncidentsPage } from './pages/Incidents/IncidentsPage';
import { IncidentDetailPage } from './pages/Incidents/IncidentDetailPage';
import { DataSourcesPage } from './pages/DataSources/DataSourcesPage';
import { SimulatorPage } from './pages/Simulator/SimulatorPage';
import { SettingsPage } from './pages/Settings/SettingsPage';

function AppContent() {
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-white text-[#171717]">
      {/* Left Navigation Sidebar (Desktop + Mobile Drawer) */}
      <Sidebar
        isOpen={mobileNavOpen}
        onClose={() => setMobileNavOpen(false)}
      />

      {/* Main Area with Header and Content */}
      <div className="flex-1 min-w-0 flex flex-col h-full overflow-hidden bg-[#fafafa]">
        {/* Top SaaS Header with Mobile Menu Button */}
        <Header onOpenMobileNav={() => setMobileNavOpen(true)} />

        {/* Main Canvas with Responsive Padding */}
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8">
          <div className="max-w-7xl mx-auto w-full">
            <Routes>
              {/* Primary 6 SaaS Routes */}
              <Route path="/" element={<OverviewPage />} />
              <Route path="/alerts" element={<AlertsPage />} />
              <Route path="/incidents" element={<IncidentsPage />} />
              <Route path="/incidents/:id" element={<IncidentDetailPage />} />
              <Route path="/sources" element={<DataSourcesPage />} />
              <Route path="/simulator" element={<SimulatorPage />} />
              <Route path="/settings" element={<SettingsPage />} />

              {/* Consolidations: legacy URLs seamlessly redirect */}
              <Route path="/mitre" element={<Navigate to="/alerts" replace />} />
              <Route path="/correlation" element={<Navigate to="/incidents" replace />} />
              <Route path="/telemetry" element={<Navigate to="/sources" replace />} />
              <Route path="/normalization" element={<Navigate to="/sources" replace />} />
              <Route path="/risk" element={<Navigate to="/settings" replace />} />
              <Route path="/bluf" element={<Navigate to="/incidents" replace />} />
              <Route path="/health" element={<Navigate to="/settings" replace />} />
              <Route path="/threat-intel" element={<Navigate to="/alerts" replace />} />

              {/* Catch-all */}
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </div>
        </main>
      </div>
    </div>
  );
}

export function App() {
  return (
    <SentinelProvider>
      <BrowserRouter>
        <AppContent />
      </BrowserRouter>
    </SentinelProvider>
  );
}

export default App;
