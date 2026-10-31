import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  ShieldCheck,
  Lock,
  Mail,
  KeyRound,
  Building2,
  AlertCircle,
  ArrowRight,
  Eye,
  EyeOff,
  User,
  Sliders,
  Sparkles,
  CheckCircle2,
  RefreshCw,
  HelpCircle,
  Globe,
  Network
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { api } from '../api/client';

interface DemoUser {
  email: string;
  name: string;
  role: 'admin' | 'user';
  orgId: string;
}

type TabType = 'signin' | 'register' | 'register-org';

export const Login: React.FC = () => {
  const { login, setSession, currentUser, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  // Active Tab
  const [activeTab, setActiveTab] = useState<TabType>('signin');

  // Shared state
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  // Sign In Form State
  const [signInEmail, setSignInEmail] = useState('');
  const [signInPassword, setSignInPassword] = useState('');

  // User Registration State
  const [regName, setRegName] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regPassword, setRegPassword] = useState('');
  const [regJoinCode, setRegJoinCode] = useState('');

  // Organization Registration State
  const [orgName, setOrgName] = useState('');
  const [orgType, setOrgType] = useState('Financial Services');
  const [orgAdminName, setOrgAdminName] = useState('');
  const [orgEmail, setOrgEmail] = useState('');
  const [orgPassword, setOrgPassword] = useState('');
  const [optInCollaborative, setOptInCollaborative] = useState(true);

  // Cyber Profile Wizard State (for new org)
  const [showProfileWizard, setShowProfileWizard] = useState(false);
  const [wizardUsersCount, setWizardUsersCount] = useState<number>(250);
  const [wizardCriticalSystems, setWizardCriticalSystems] = useState<number>(12);
  const [wizardInternetFacing, setWizardInternetFacing] = useState<number>(6);
  const [wizardDataSensitivity, setWizardDataSensitivity] = useState<'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'>('HIGH');
  const [wizardPreviousIncidents, setWizardPreviousIncidents] = useState<number>(0);

  // Forgot Password Flow State
  const [showForgotModal, setShowForgotModal] = useState(false);
  const [forgotStep, setForgotStep] = useState<1 | 2 | 3>(1);
  const [forgotEmail, setForgotEmail] = useState('');
  const [forgotCode, setForgotCode] = useState('');
  const [forgotResetToken, setForgotResetToken] = useState('');
  const [forgotNewPassword, setForgotNewPassword] = useState('');
  const [simulatedDemoCode, setSimulatedDemoCode] = useState<string | null>(null);

  // Demo users from backend
  const [demoUsers, setDemoUsers] = useState<DemoUser[]>([]);
  const [isDemoMode, setIsDemoMode] = useState(false);

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated && currentUser) {
      if (currentUser.role === 'admin') {
        navigate('/', { replace: true });
      } else {
        navigate('/my-account', { replace: true });
      }
    }
  }, [isAuthenticated, currentUser, navigate]);

  // Load demo users from backend if DEMO_MODE is active
  useEffect(() => {
    api.get<{ accounts: DemoUser[]; isPrototype: boolean }>('/api/auth/demo-users')
      .then((res) => {
        if (res && res.accounts && res.accounts.length > 0) {
          setDemoUsers(res.accounts);
          setIsDemoMode(true);
        }
      })
      .catch(() => {
        setIsDemoMode(false);
      });
  }, []);

  // Check URL query parameters
  useEffect(() => {
    if (searchParams.get('expired') === 'true') {
      setError('Your security session was expired or revoked by an administrator. Please sign in again.');
    } else if (searchParams.get('locked') === 'true') {
      setError('Your account was locked by an administrator for containment. Please contact your SOC administrator.');
    }
  }, [searchParams]);

  // Password strength calculation
  const calculatePasswordStrength = (pass: string): { score: number; label: string; color: string } => {
    if (!pass) return { score: 0, label: '', color: 'bg-slate-700' };
    let score = 0;
    if (pass.length >= 8) score += 1;
    if (/[A-Z]/.test(pass) && /[a-z]/.test(pass)) score += 1;
    if (/\d/.test(pass)) score += 1;
    if (/[^A-Za-z0-9]/.test(pass)) score += 1;

    switch (score) {
      case 1:
        return { score: 25, label: 'Weak (needs letter + number)', color: 'bg-rose-500' };
      case 2:
        return { score: 50, label: 'Fair (add special character)', color: 'bg-amber-500' };
      case 3:
        return { score: 75, label: 'Good (strong protection)', color: 'bg-cyan-500' };
      case 4:
        return { score: 100, label: 'Strong (production grade)', color: 'bg-emerald-500' };
      default:
        return { score: 10, label: 'Too short', color: 'bg-rose-600' };
    }
  };

  // Sign In Handler
  const handleSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);
    setLoading(true);

    const res = await login(signInEmail, signInPassword);
    setLoading(false);

    if (res.success && res.user) {
      if (res.user.role === 'admin') {
        navigate('/');
      } else {
        navigate('/my-account');
      }
    } else {
      setError(res.error || 'Invalid email or password.');
    }
  };

  // User Registration Handler
  const handleRegisterUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    if (!regName.trim() || !regEmail.trim() || !regPassword || !regJoinCode.trim()) {
      setError('All fields are required.');
      return;
    }

    if (regPassword.length < 8 || !/(?=.*[A-Za-z])(?=.*\d)/.test(regPassword)) {
      setError('Password must be at least 8 characters long and contain both letters and numbers.');
      return;
    }

    setLoading(true);
    try {
      const res = await api.post<{ success: boolean; message: string; requiresApproval: boolean }>('/api/auth/register', {
        name: regName.trim(),
        email: regEmail.trim(),
        password: regPassword,
        joinCode: regJoinCode.trim().toUpperCase()
      });

      setLoading(false);
      if (res && res.success) {
        if (res.requiresApproval) {
          setSuccessMsg('Account created! Your registration is awaiting approval by your organization SOC administrator.');
          setActiveTab('signin');
        } else {
          setSuccessMsg('Account created successfully! Signing you in...');
          // Auto login
          const loginRes = await login(regEmail.trim(), regPassword);
          if (loginRes.success) {
            navigate('/my-account');
          } else {
            setActiveTab('signin');
          }
        }
      }
    } catch (err: any) {
      setLoading(false);
      setError(err.message || 'Registration failed.');
    }
  };

  // Organization Registration Handler
  const handleRegisterOrg = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    if (!orgName.trim() || !orgType || !orgAdminName.trim() || !orgEmail.trim() || !orgPassword) {
      setError('All organization and administrator fields are required.');
      return;
    }

    if (orgPassword.length < 8 || !/(?=.*[A-Za-z])(?=.*\d)/.test(orgPassword)) {
      setError('Password must be at least 8 characters long and contain both letters and numbers.');
      return;
    }

    setLoading(true);
    try {
      const res = await api.post<{
        success: boolean;
        token: string;
        user: any;
        org: { id: string; name: string; joinCode: string; riskScore: number };
      }>('/api/auth/register-organization', {
        orgName: orgName.trim(),
        orgType: orgType.trim(),
        adminName: orgAdminName.trim(),
        email: orgEmail.trim(),
        password: orgPassword,
        cyberProfile: {
          usersCount: wizardUsersCount,
          criticalSystems: wizardCriticalSystems,
          internetFacingServices: wizardInternetFacing,
          dataSensitivity: wizardDataSensitivity,
          previousIncidents: wizardPreviousIncidents,
          optInCollaborative
        }
      });

      setLoading(false);
      if (res && res.token && res.user) {
        setSession(res.token, res.user);
        navigate('/');
      }
    } catch (err: any) {
      setLoading(false);
      setError(err.message || 'Organization registration failed.');
    }
  };

  // Load sample profile data in demo mode
  const handleLoadSampleProfile = () => {
    setOrgName('Titan Financial Defense');
    setOrgType('Financial Services');
    setOrgAdminName('Elena Vance');
    setOrgEmail(`elena.vance_${Date.now().toString().slice(-4)}@titanfin.com`);
    setOrgPassword('DefensePass123!');
    setWizardUsersCount(1200);
    setWizardCriticalSystems(28);
    setWizardInternetFacing(14);
    setWizardDataSensitivity('CRITICAL');
    setWizardPreviousIncidents(1);
    setOptInCollaborative(true);
  };

  // Forgot Password: Step 1 Request
  const handleForgotRequest = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const res = await api.post<{ success: boolean; demoCode?: string; message: string }>('/api/auth/forgot-password/request', {
        email: forgotEmail.trim()
      });
      setLoading(false);
      if (res.demoCode) {
        setSimulatedDemoCode(res.demoCode);
      }
      setForgotStep(2);
    } catch (err: any) {
      setLoading(false);
      setError(err.message || 'Failed to request reset code.');
    }
  };

  // Forgot Password: Step 2 Verify Code
  const handleForgotVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const res = await api.post<{ success: boolean; resetToken: string }>('/api/auth/forgot-password/verify', {
        email: forgotEmail.trim(),
        code: forgotCode.trim()
      });
      setLoading(false);
      if (res && res.resetToken) {
        setForgotResetToken(res.resetToken);
        setForgotStep(3);
      }
    } catch (err: any) {
      setLoading(false);
      setError(err.message || 'Invalid verification code.');
    }
  };

  // Forgot Password: Step 3 Reset
  const handleForgotReset = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    if (forgotNewPassword.length < 8 || !/(?=.*[A-Za-z])(?=.*\d)/.test(forgotNewPassword)) {
      setError('Password must be at least 8 characters long and contain both letters and numbers.');
      setLoading(false);
      return;
    }

    try {
      const res = await api.post<{ success: boolean; message: string }>('/api/auth/forgot-password/reset', {
        email: forgotEmail.trim(),
        resetToken: forgotResetToken,
        newPassword: forgotNewPassword
      });
      setLoading(false);
      setShowForgotModal(false);
      setForgotStep(1);
      setForgotEmail('');
      setForgotCode('');
      setForgotResetToken('');
      setForgotNewPassword('');
      setSimulatedDemoCode(null);
      setSuccessMsg(res.message || 'Password updated! You can now sign in.');
      setActiveTab('signin');
    } catch (err: any) {
      setLoading(false);
      setError(err.message || 'Failed to reset password.');
    }
  };

  const handleSelectDemoUser = (user: DemoUser) => {
    setActiveTab('signin');
    setSignInEmail(user.email);
    setSignInPassword(user.role === 'admin' ? 'AdminPass123!' : 'UserPass123!');
    setError(null);
  };

  const currentStrength = activeTab === 'register'
    ? calculatePasswordStrength(regPassword)
    : activeTab === 'register-org'
    ? calculatePasswordStrength(orgPassword)
    : calculatePasswordStrength(forgotNewPassword);

  return (
    <div className="min-h-screen bg-[#0B0F17] text-slate-100 flex flex-col justify-center items-center px-4 py-8 relative">
      {/* Background Glow */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-lg bg-[#0F1420] border border-slate-800 rounded-2xl p-6 sm:p-8 shadow-2xl relative z-10">
        {/* Brand Header */}
        <div className="text-center mb-6">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-600 p-0.5 shadow-lg shadow-cyan-500/20 mb-3">
            <div className="w-full h-full bg-[#0B0F17] rounded-[14px] flex items-center justify-center">
              <ShieldCheck className="w-8 h-8 text-cyan-400" />
            </div>
          </div>
          <h1 className="text-xl font-bold tracking-wider uppercase text-slate-100">
            CYBERGUARD <span className="text-cyan-400">GRID</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">INSTITUTIONAL ACCESS & SOC CONSOLE</p>
        </div>

        {/* Navigation Tabs */}
        <div className="grid grid-cols-3 gap-1 p-1 bg-[#0B0F17] border border-slate-800 rounded-xl mb-6 text-xs font-semibold">
          <button
            type="button"
            onClick={() => { setActiveTab('signin'); setError(null); }}
            className={`py-2 rounded-lg transition-all text-center ${
              activeTab === 'signin'
                ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 font-bold shadow-md shadow-cyan-500/20'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Sign In
          </button>
          <button
            type="button"
            onClick={() => { setActiveTab('register'); setError(null); }}
            className={`py-2 rounded-lg transition-all text-center ${
              activeTab === 'register'
                ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 font-bold shadow-md shadow-cyan-500/20'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Create Account
          </button>
          <button
            type="button"
            onClick={() => { setActiveTab('register-org'); setError(null); }}
            className={`py-2 rounded-lg transition-all text-center ${
              activeTab === 'register-org'
                ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 font-bold shadow-md shadow-cyan-500/20'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Register Org
          </button>
        </div>

        {/* Global Error Banner */}
        {error && (
          <div className="mb-5 p-3 rounded-lg bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs flex items-start space-x-2">
            <AlertCircle className="w-4 h-4 shrink-0 text-rose-400 mt-0.5" />
            <span className="leading-relaxed">{error}</span>
          </div>
        )}

        {/* Global Success Banner */}
        {successMsg && (
          <div className="mb-5 p-3 rounded-lg bg-emerald-950/40 border border-emerald-500/40 text-emerald-300 text-xs flex items-start space-x-2">
            <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400 mt-0.5" />
            <span className="leading-relaxed">{successMsg}</span>
          </div>
        )}

        {/* TAB 1: SIGN IN */}
        {activeTab === 'signin' && (
          <form onSubmit={handleSignIn} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">Workplace Email</label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="email"
                  value={signInEmail}
                  onChange={(e) => setSignInEmail(e.target.value)}
                  placeholder="name@organization.com"
                  required
                  className="w-full bg-[#0B0F17] border border-slate-700/80 rounded-lg pl-10 pr-3.5 py-2.5 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-xs font-medium text-slate-300">Password</label>
                <button
                  type="button"
                  onClick={() => { setShowForgotModal(true); setError(null); }}
                  className="text-xs text-cyan-400 hover:text-cyan-300 transition"
                >
                  Forgot password?
                </button>
              </div>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={signInPassword}
                  onChange={(e) => setSignInPassword(e.target.value)}
                  placeholder="••••••••••••"
                  required
                  className="w-full bg-[#0B0F17] border border-slate-700/80 rounded-lg pl-10 pr-10 py-2.5 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full mt-2 py-2.5 px-4 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-semibold text-sm rounded-lg shadow-lg shadow-cyan-500/20 transition-all flex items-center justify-center space-x-2"
            >
              <span>{loading ? 'Authenticating...' : 'Sign In'}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>
        )}

        {/* TAB 2: CREATE ACCOUNT (Standard User via Join Code) */}
        {activeTab === 'register' && (
          <form onSubmit={handleRegisterUser} className="space-y-3.5">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Full Name</label>
              <div className="relative">
                <User className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={regName}
                  onChange={(e) => setRegName(e.target.value)}
                  placeholder="Jane Doe"
                  required
                  className="w-full bg-[#0B0F17] border border-slate-700/80 rounded-lg pl-10 pr-3.5 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Workplace Email</label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="email"
                  value={regEmail}
                  onChange={(e) => setRegEmail(e.target.value)}
                  placeholder="jane.doe@organization.com"
                  required
                  className="w-full bg-[#0B0F17] border border-slate-700/80 rounded-lg pl-10 pr-3.5 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Organization Join Code</label>
              <div className="relative">
                <Building2 className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={regJoinCode}
                  onChange={(e) => setRegJoinCode(e.target.value.toUpperCase())}
                  placeholder="e.g. BANK-A01"
                  required
                  className="w-full bg-[#0B0F17] border border-slate-700/80 rounded-lg pl-10 pr-3.5 py-2 text-sm text-cyan-300 font-mono placeholder-slate-500 focus:outline-none focus:border-cyan-500 tracking-wider"
                />
              </div>
              <p className="text-[11px] text-slate-400 mt-1 flex items-center space-x-1">
                <HelpCircle className="w-3 h-3 text-slate-500 shrink-0" />
                <span>Join codes are issued by your institutional SOC admin (e.g. BANK-A01).</span>
              </p>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Password</label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={regPassword}
                  onChange={(e) => setRegPassword(e.target.value)}
                  placeholder="Min 8 characters (letters + numbers)"
                  required
                  className="w-full bg-[#0B0F17] border border-slate-700/80 rounded-lg pl-10 pr-10 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>

              {/* Strength Meter */}
              {regPassword && (
                <div className="mt-2 space-y-1">
                  <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                    <div
                      className={`h-full transition-all duration-300 ${currentStrength.color}`}
                      style={{ width: `${currentStrength.score}%` }}
                    />
                  </div>
                  <div className="flex justify-between text-[10px] text-slate-400 font-mono">
                    <span>Strength: {currentStrength.label}</span>
                    <span>{currentStrength.score}%</span>
                  </div>
                </div>
              )}
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full mt-3 py-2.5 px-4 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-semibold text-sm rounded-lg shadow-lg shadow-cyan-500/20 transition-all flex items-center justify-center space-x-2"
            >
              <span>{loading ? 'Registering...' : 'Create Account'}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>
        )}

        {/* TAB 3: REGISTER ORGANIZATION (Admin Onboarding) */}
        {activeTab === 'register-org' && (
          <form onSubmit={handleRegisterOrg} className="space-y-3.5">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-semibold text-cyan-400 uppercase tracking-wider">Institution Setup</span>
              {isDemoMode && (
                <button
                  type="button"
                  onClick={handleLoadSampleProfile}
                  className="text-[11px] text-cyan-400 hover:text-cyan-300 bg-cyan-950/60 border border-cyan-800/80 px-2 py-0.5 rounded flex items-center space-x-1"
                >
                  <Sparkles className="w-3 h-3" />
                  <span>Load Sample Data</span>
                </button>
              )}
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Organization Name</label>
                <input
                  type="text"
                  value={orgName}
                  onChange={(e) => setOrgName(e.target.value)}
                  placeholder="Acme Financial"
                  required
                  className="w-full bg-[#0B0F17] border border-slate-700/80 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Sector / Type</label>
                <select
                  value={orgType}
                  onChange={(e) => setOrgType(e.target.value)}
                  className="w-full bg-[#0B0F17] border border-slate-700/80 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="Financial Services">Financial Services</option>
                  <option value="Healthcare & Lifesciences">Healthcare & Lifesciences</option>
                  <option value="Education & Research">Education & Research</option>
                  <option value="Defense & Aerospace">Defense & Aerospace</option>
                  <option value="Critical Infrastructure">Critical Infrastructure</option>
                  <option value="Technology & SaaS">Technology & SaaS</option>
                </select>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Lead Admin Name</label>
                <input
                  type="text"
                  value={orgAdminName}
                  onChange={(e) => setOrgAdminName(e.target.value)}
                  placeholder="Samantha Carter"
                  required
                  className="w-full bg-[#0B0F17] border border-slate-700/80 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Admin Email</label>
                <input
                  type="email"
                  value={orgEmail}
                  onChange={(e) => setOrgEmail(e.target.value)}
                  placeholder="admin@acme.com"
                  required
                  className="w-full bg-[#0B0F17] border border-slate-700/80 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Admin Password</label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={orgPassword}
                  onChange={(e) => setOrgPassword(e.target.value)}
                  placeholder="Min 8 characters (letters + numbers)"
                  required
                  className="w-full bg-[#0B0F17] border border-slate-700/80 rounded-lg pl-3 pr-10 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {orgPassword && (
                <div className="mt-2 space-y-1">
                  <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                    <div
                      className={`h-full transition-all duration-300 ${currentStrength.color}`}
                      style={{ width: `${currentStrength.score}%` }}
                    />
                  </div>
                  <div className="flex justify-between text-[10px] text-slate-400 font-mono">
                    <span>Strength: {currentStrength.label}</span>
                    <span>{currentStrength.score}%</span>
                  </div>
                </div>
              )}
            </div>

            {/* Collaborative Network Opt-In */}
            <div className="p-3 rounded-xl bg-[#0B0F17] border border-slate-800 flex items-start justify-between gap-3">
              <div className="flex items-start space-x-2.5">
                <Network className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                <div>
                  <div className="text-xs font-semibold text-slate-200">Collaborative Threat Mesh</div>
                  <p className="text-[11px] text-slate-400 leading-snug">
                    Share privacy-preserving, zero-raw-data threat intelligence with peer institutions.
                  </p>
                </div>
              </div>
              <input
                type="checkbox"
                checked={optInCollaborative}
                onChange={(e) => setOptInCollaborative(e.target.checked)}
                className="w-4 h-4 mt-0.5 rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-cyan-500 cursor-pointer"
              />
            </div>

            {/* Expandable Cyber Profile Wizard */}
            <div className="border border-slate-800 rounded-xl overflow-hidden bg-[#0B0F17]">
              <button
                type="button"
                onClick={() => setShowProfileWizard(!showProfileWizard)}
                className="w-full p-3 flex items-center justify-between text-xs font-semibold text-slate-300 hover:text-cyan-400 transition"
              >
                <span className="flex items-center space-x-2">
                  <Sliders className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Cyber Profile Baseline (Optional Setup)</span>
                </span>
                <span className="text-[11px] text-cyan-400 font-mono">{showProfileWizard ? 'Hide' : 'Configure'}</span>
              </button>

              {showProfileWizard && (
                <div className="p-3.5 border-t border-slate-800 space-y-3 text-xs bg-slate-950/40">
                  <div className="grid grid-cols-3 gap-2">
                    <div>
                      <label className="text-[11px] text-slate-400 block mb-1">Users Count</label>
                      <input
                        type="number"
                        min="1"
                        value={wizardUsersCount}
                        onChange={(e) => setWizardUsersCount(Number(e.target.value) || 1)}
                        className="w-full bg-[#0F1420] border border-slate-800 rounded px-2 py-1 text-slate-200"
                      />
                    </div>
                    <div>
                      <label className="text-[11px] text-slate-400 block mb-1">Critical Systems</label>
                      <input
                        type="number"
                        min="1"
                        value={wizardCriticalSystems}
                        onChange={(e) => setWizardCriticalSystems(Number(e.target.value) || 1)}
                        className="w-full bg-[#0F1420] border border-slate-800 rounded px-2 py-1 text-slate-200"
                      />
                    </div>
                    <div>
                      <label className="text-[11px] text-slate-400 block mb-1">Internet Services</label>
                      <input
                        type="number"
                        min="1"
                        value={wizardInternetFacing}
                        onChange={(e) => setWizardInternetFacing(Number(e.target.value) || 1)}
                        className="w-full bg-[#0F1420] border border-slate-800 rounded px-2 py-1 text-slate-200"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <label className="text-[11px] text-slate-400 block mb-1">Data Sensitivity</label>
                      <select
                        value={wizardDataSensitivity}
                        onChange={(e) => setWizardDataSensitivity(e.target.value as any)}
                        className="w-full bg-[#0F1420] border border-slate-800 rounded px-2 py-1 text-slate-200"
                      >
                        <option value="LOW">Low</option>
                        <option value="MEDIUM">Medium</option>
                        <option value="HIGH">High</option>
                        <option value="CRITICAL">Critical</option>
                      </select>
                    </div>
                    <div>
                      <label className="text-[11px] text-slate-400 block mb-1">Past Incidents</label>
                      <input
                        type="number"
                        min="0"
                        value={wizardPreviousIncidents}
                        onChange={(e) => setWizardPreviousIncidents(Number(e.target.value) || 0)}
                        className="w-full bg-[#0F1420] border border-slate-800 rounded px-2 py-1 text-slate-200"
                      />
                    </div>
                  </div>
                </div>
              )}
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full mt-3 py-2.5 px-4 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-semibold text-sm rounded-lg shadow-lg shadow-cyan-500/20 transition-all flex items-center justify-center space-x-2"
            >
              <span>{loading ? 'Provisioning Organization...' : 'Register Organization & Access SOC'}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>
        )}

        {/* Demo Accounts Quick-Fill Chips (Rendered only on Sign In tab in DEMO_MODE) */}
        {activeTab === 'signin' && isDemoMode && demoUsers.length > 0 && (
          <div className="mt-6 pt-5 border-t border-slate-800">
            <div className="flex items-center justify-between mb-3">
              <span className="text-[11px] font-semibold text-cyan-400 uppercase tracking-wider flex items-center space-x-1.5">
                <KeyRound className="w-3.5 h-3.5" />
                <span>Demo Accounts Quick-Fill</span>
              </span>
              <span className="text-[10px] bg-slate-800 text-slate-400 px-2 py-0.5 rounded font-mono">DEMO MODE</span>
            </div>

            <p className="text-[11px] text-slate-400 mb-3">
              Click an account to autofill credentials (<code className="text-cyan-300">AdminPass123!</code> / <code className="text-cyan-300">UserPass123!</code>):
            </p>

            <div className="grid grid-cols-2 gap-2">
              {demoUsers.map((u) => {
                const isSelected = signInEmail === u.email;
                const isAdmin = u.role === 'admin';
                return (
                  <button
                    key={u.email}
                    type="button"
                    onClick={() => handleSelectDemoUser(u)}
                    className={`p-2 rounded-lg border text-left transition-all ${
                      isSelected
                        ? 'bg-cyan-950/60 border-cyan-500 text-cyan-200 shadow-md shadow-cyan-950/50'
                        : 'bg-[#0B0F17] hover:bg-slate-800/60 border-slate-800 text-slate-300'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-0.5">
                      <span className="text-[11px] font-semibold truncate">{u.name}</span>
                      <span
                        className={`text-[9px] px-1.5 py-0.2 rounded font-mono font-bold ${
                          isAdmin
                            ? 'bg-cyan-950 text-cyan-400 border border-cyan-800'
                            : 'bg-slate-800 text-slate-400 border border-slate-700'
                        }`}
                      >
                        {isAdmin ? 'SOC' : 'USER'}
                      </span>
                    </div>
                    <div className="text-[10px] text-slate-500 flex items-center space-x-1 truncate">
                      <Building2 className="w-2.5 h-2.5 shrink-0" />
                      <span className="truncate">{u.orgId}</span>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        )}

        <div className="mt-5 text-center">
          <p className="text-[10px] text-slate-500">
            Protected under Role-Based Access Control (RBAC). Admin actions are cryptographically signed & audited.
          </p>
        </div>
      </div>

      {/* FORGOT PASSWORD MODAL */}
      {showForgotModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="w-full max-w-md bg-[#0F1420] border border-slate-800 rounded-2xl p-6 shadow-2xl relative">
            <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2">
                <Lock className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-slate-100">Reset Credentials</h3>
              </div>
              <button
                type="button"
                onClick={() => { setShowForgotModal(false); setForgotStep(1); setSimulatedDemoCode(null); }}
                className="text-slate-400 hover:text-slate-200 text-xs"
              >
                Cancel
              </button>
            </div>

            {/* Step 1: Request Code */}
            {forgotStep === 1 && (
              <form onSubmit={handleForgotRequest} className="space-y-4">
                <p className="text-xs text-slate-300 leading-relaxed">
                  Enter your workplace email address. We will send a secure 6-digit verification code to confirm your identity.
                </p>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Workplace Email</label>
                  <input
                    type="email"
                    value={forgotEmail}
                    onChange={(e) => setForgotEmail(e.target.value)}
                    placeholder="name@organization.com"
                    required
                    className="w-full bg-[#0B0F17] border border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 font-semibold text-xs rounded-lg shadow-md transition flex items-center justify-center space-x-2"
                >
                  <span>{loading ? 'Sending Code...' : 'Request Verification Code'}</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </form>
            )}

            {/* Step 2: Enter 6-digit Code */}
            {forgotStep === 2 && (
              <form onSubmit={handleForgotVerify} className="space-y-4">
                <p className="text-xs text-slate-300 leading-relaxed">
                  Enter the 6-digit verification code dispatched to <span className="text-cyan-400 font-mono">{forgotEmail}</span>.
                </p>

                {simulatedDemoCode && (
                  <div className="p-3 bg-cyan-950/60 border border-cyan-800 rounded-xl flex items-center justify-between">
                    <div>
                      <div className="text-[10px] uppercase font-mono text-cyan-400 font-bold">Simulated Email Code</div>
                      <div className="text-base font-bold font-mono text-cyan-300 tracking-widest">{simulatedDemoCode}</div>
                    </div>
                    <button
                      type="button"
                      onClick={() => setForgotCode(simulatedDemoCode)}
                      className="text-xs bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 px-2.5 py-1 rounded"
                    >
                      Autofill Code
                    </button>
                  </div>
                )}

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">6-Digit Code</label>
                  <input
                    type="text"
                    maxLength={6}
                    value={forgotCode}
                    onChange={(e) => setForgotCode(e.target.value.replace(/\D/g, ''))}
                    placeholder="123456"
                    required
                    className="w-full bg-[#0B0F17] border border-slate-700/80 rounded-lg px-3.5 py-2 text-center text-lg text-cyan-300 font-mono tracking-widest focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading || forgotCode.length !== 6}
                  className="w-full py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 font-semibold text-xs rounded-lg shadow-md transition flex items-center justify-center space-x-2 disabled:opacity-50"
                >
                  <span>{loading ? 'Verifying...' : 'Verify Code'}</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </form>
            )}

            {/* Step 3: Enter New Password */}
            {forgotStep === 3 && (
              <form onSubmit={handleForgotReset} className="space-y-4">
                <p className="text-xs text-slate-300 leading-relaxed">
                  Verification successful. Choose a new secure password for your account.
                </p>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">New Password</label>
                  <input
                    type="password"
                    value={forgotNewPassword}
                    onChange={(e) => setForgotNewPassword(e.target.value)}
                    placeholder="Min 8 characters (letters + numbers)"
                    required
                    className="w-full bg-[#0B0F17] border border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                  />
                  {forgotNewPassword && (
                    <div className="mt-2 space-y-1">
                      <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                        <div
                          className={`h-full transition-all duration-300 ${currentStrength.color}`}
                          style={{ width: `${currentStrength.score}%` }}
                        />
                      </div>
                      <div className="flex justify-between text-[10px] text-slate-400 font-mono">
                        <span>Strength: {currentStrength.label}</span>
                        <span>{currentStrength.score}%</span>
                      </div>
                    </div>
                  )}
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 font-semibold text-xs rounded-lg shadow-md transition flex items-center justify-center space-x-2"
                >
                  <span>{loading ? 'Updating Password...' : 'Save New Password'}</span>
                  <CheckCircle2 className="w-3.5 h-3.5" />
                </button>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
