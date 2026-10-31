import React, { createContext, useContext, useState, useEffect, ReactNode, useCallback } from 'react';
import { AuthUser } from '../types';
import { api, registerAuthCallbacks } from '../api/client';

interface AuthContextType {
  currentUser: AuthUser | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoadingAuth: boolean;
  login: (email: string, password: string) => Promise<{ success: boolean; error?: string; user?: AuthUser }>;
  setSession: (token: string, user: AuthUser) => void;
  logout: () => Promise<void>;
  resetPassword: (newPassword: string) => Promise<{ success: boolean; error?: string }>;
  checkSession: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [token, setToken] = useState<string | null>(() => {
    return localStorage.getItem('cyberguard_token');
  });

  const [currentUser, setCurrentUser] = useState<AuthUser | null>(() => {
    try {
      const stored = localStorage.getItem('cyberguard_user');
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  });

  const [isLoadingAuth, setIsLoadingAuth] = useState<boolean>(true);

  const logout = useCallback(async () => {
    const storedToken = localStorage.getItem('cyberguard_token');
    if (storedToken) {
      try {
        await api.post('/api/auth/logout', {}).catch(() => {});
      } catch {
        // best effort
      }
    }
    localStorage.removeItem('cyberguard_token');
    localStorage.removeItem('cyberguard_user');
    setToken(null);
    setCurrentUser(null);
    // Dispatch custom event to notify components & close open WebSockets
    window.dispatchEvent(new CustomEvent('cyberguard:logout'));
  }, []);

  const checkSession = useCallback(async () => {
    const storedToken = localStorage.getItem('cyberguard_token');
    if (!storedToken) {
      setToken(null);
      setCurrentUser(null);
      setIsLoadingAuth(false);
      return;
    }

    try {
      const res = await api.get<{ user: AuthUser }>('/api/auth/me');
      if (res && res.user) {
        setCurrentUser(res.user);
        setToken(storedToken);
        localStorage.setItem('cyberguard_user', JSON.stringify(res.user));
      } else {
        await logout();
      }
    } catch (err: any) {
      // 401 or 403 handling is managed by apiClient
      setCurrentUser(null);
      setToken(null);
    } finally {
      setIsLoadingAuth(false);
    }
  }, [logout]);

  useEffect(() => {
    registerAuthCallbacks(
      () => {
        // On 401 Unauthorized
        setToken(null);
        setCurrentUser(null);
        window.dispatchEvent(new CustomEvent('cyberguard:logout'));
      },
      (err) => {
        // On 403 Forbidden
        if (err?.error === 'ACCOUNT_LOCKED') {
          setToken(null);
          setCurrentUser(null);
          window.dispatchEvent(new CustomEvent('cyberguard:logout'));
        }
      }
    );

    checkSession();
  }, [checkSession]);

  const setSession = useCallback((newToken: string, newUser: AuthUser) => {
    localStorage.setItem('cyberguard_token', newToken);
    localStorage.setItem('cyberguard_user', JSON.stringify(newUser));
    setToken(newToken);
    setCurrentUser(newUser);
  }, []);

  const login = async (
    email: string,
    password: string
  ): Promise<{ success: boolean; error?: string; user?: AuthUser }> => {
    try {
      const data = await api.post<{ token: string; user: AuthUser }>('/api/auth/login', { email, password });
      if (data && data.token && data.user) {
        localStorage.setItem('cyberguard_token', data.token);
        localStorage.setItem('cyberguard_user', JSON.stringify(data.user));
        setToken(data.token);
        setCurrentUser(data.user);
        return { success: true, user: data.user };
      }
      return { success: false, error: 'Malformed authentication response.' };
    } catch (err: any) {
      return { success: false, error: err.message || 'Authentication failed.' };
    }
  };

  const resetPassword = async (
    newPassword: string
  ): Promise<{ success: boolean; error?: string }> => {
    try {
      await api.post('/api/auth/reset-password', { newPassword });
      if (currentUser) {
        const updated: AuthUser = { ...currentUser, mustReset: false, status: 'active' };
        setCurrentUser(updated);
        localStorage.setItem('cyberguard_user', JSON.stringify(updated));
      }
      return { success: true };
    } catch (err: any) {
      return { success: false, error: err.message || 'Failed to update credentials.' };
    }
  };

  const isAuthenticated = Boolean(token && currentUser);

  return (
    <AuthContext.Provider
      value={{
        currentUser,
        token,
        isAuthenticated,
        isLoadingAuth,
        login,
        setSession,
        logout,
        resetPassword,
        checkSession
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

