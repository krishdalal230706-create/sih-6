import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { AppProvider } from './context/AppContext';
import { Sidebar } from './components/layout/Sidebar';
import { Topbar } from './components/layout/Topbar';
import { DemoModeController } from './components/demo/DemoModeController';

import { Overview } from './pages/Overview';
import { CyberRisk } from './pages/CyberRisk';
import { AttackSimulator } from './pages/AttackSimulator';
import { AttackPath } from './pages/AttackPath';
import { ThreatDetection } from './pages/ThreatDetection';
import { Incidents } from './pages/Incidents';
import { ResponseCenter } from './pages/ResponseCenter';
import { PrivacyEngine } from './pages/PrivacyEngine';
import { ThreatIntelligence } from './pages/ThreatIntelligence';
import { CollaborativeNetwork } from './pages/CollaborativeNetwork';
import { DLTLedger } from './pages/DLTLedger';
import { Organizations } from './pages/Organizations';
import { Reports } from './pages/Reports';
import { Settings } from './pages/Settings';
import { InvestmentOptimization } from './pages/InvestmentOptimization';

export const App: React.FC = () => {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = React.useState(false);

  return (
    <Router>
      <AppProvider>
        <div className="flex h-screen bg-[#0B0F17] text-slate-100 font-sans overflow-hidden">
          {/* Left Navigation Sidebar */}
          <Sidebar isOpen={isMobileMenuOpen} onClose={() => setIsMobileMenuOpen(false)} />

          {/* Main Content Workspace */}
          <div className="flex-1 flex flex-col min-w-0 overflow-hidden relative">
            {/* Top Bar */}
            <Topbar onMenuToggle={() => setIsMobileMenuOpen(!isMobileMenuOpen)} />

            {/* Scrollable Page Body */}
            <main className="flex-1 overflow-y-auto pb-24">
              <Routes>
                <Route path="/" element={<Overview />} />
                <Route path="/cyber-risk" element={<CyberRisk />} />
                <Route path="/attack-simulator" element={<AttackSimulator />} />
                <Route path="/attack-path" element={<AttackPath />} />
                <Route path="/threat-detection" element={<ThreatDetection />} />
                <Route path="/incidents" element={<Incidents />} />
                <Route path="/response-center" element={<ResponseCenter />} />
                <Route path="/investment-optimization" element={<InvestmentOptimization />} />
                <Route path="/privacy-engine" element={<PrivacyEngine />} />
                <Route path="/threat-intelligence" element={<ThreatIntelligence />} />
                <Route path="/collaborative-network" element={<CollaborativeNetwork />} />
                <Route path="/dlt-ledger" element={<DLTLedger />} />
                <Route path="/organizations" element={<Organizations />} />
                <Route path="/reports" element={<Reports />} />
                <Route path="/settings" element={<Settings />} />
              </Routes>
            </main>

            {/* Interactive 14-Step Demo Mode Floating Controller */}
            <DemoModeController />
          </div>
        </div>
      </AppProvider>
    </Router>
  );
};

export default App;
