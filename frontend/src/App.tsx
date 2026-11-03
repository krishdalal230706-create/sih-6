import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { AuthProvider } from './context/AuthContext';
import { AppProvider } from './context/AppContext';
import { AdminLayout } from './components/layout/AdminLayout';
import { UserLayout } from './components/layout/UserLayout';

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
import { Login } from './pages/Login';
import { MyAccount } from './pages/MyAccount';
import { AccountSecurity } from './pages/AccountSecurity';
import { AccountDetail } from './pages/AccountDetail';
import { Endpoints } from './pages/Endpoints';
import { DeviceDetail } from './pages/DeviceDetail';
import { BankAssets } from './pages/BankAssets';
import { AuditLog } from './pages/AuditLog';
import { Forbidden } from './pages/Forbidden';
import { NotFound } from './pages/NotFound';

export const App: React.FC = () => {
  return (
    <Router>
      <ThemeProvider>
        <AuthProvider>
          <AppProvider>
            <Routes>
              {/* Standalone Authentication & Status Routes */}
              <Route path="/login" element={<Login />} />
              <Route path="/403" element={<Forbidden />} />
              <Route path="/404" element={<NotFound />} />

              {/* Standard User Portal (role=user or authenticated view) */}
              <Route element={<UserLayout />}>
                <Route path="/my-account" element={<MyAccount />} />
                <Route path="/my-device" element={<Navigate to="/my-account" replace />} />
              </Route>

              {/* Admin Institutional SOC Console (role=admin only) */}
              <Route element={<AdminLayout />}>
                <Route path="/" element={<Overview />} />
                <Route path="/bank-assets" element={<BankAssets />} />
                <Route path="/account-security" element={<AccountSecurity />} />
                <Route path="/account-security/:userId" element={<AccountDetail />} />
                <Route path="/endpoints" element={<Endpoints />} />
                <Route path="/endpoints/:id" element={<DeviceDetail />} />
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
                <Route path="/audit-log" element={<AuditLog />} />
                <Route path="/organizations" element={<Organizations />} />
                <Route path="/reports" element={<Reports />} />
                <Route path="/settings" element={<Settings />} />
              </Route>

              {/* True 404 handler: Replaces previous catch-all redirect to "/" */}
              <Route path="*" element={<Navigate to="/404" replace />} />
            </Routes>
          </AppProvider>
        </AuthProvider>
      </ThemeProvider>
    </Router>
  );
};

export default App;
