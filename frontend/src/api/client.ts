// Central API Client for CyberGuard Grid
// Attaches Bearer token, enforces session expiration redirect, and standardizes error responses.

export interface ApiError {
  error: string;
  message: string;
  status: number;
}

type AuthCallback = () => void;
let onUnauthorizedCallback: AuthCallback | null = null;
let onForbiddenCallback: ((detail: any) => void) | null = null;

export function registerAuthCallbacks(
  onUnauthorized: AuthCallback,
  onForbidden?: (detail: any) => void
) {
  onUnauthorizedCallback = onUnauthorized;
  if (onForbidden) onForbiddenCallback = onForbidden;
}

export async function apiClient<T = any>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const token = localStorage.getItem('cyberguard_token');

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> || {})
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  // Format URL cleanly
  const baseUrl = (import.meta as any).env?.VITE_API_URL || '';
  const url = endpoint.startsWith('http') ? endpoint : `${baseUrl}${endpoint}`;

  let response: Response;
  try {
    response = await fetch(url, {
      ...options,
      headers
    });
  } catch (networkErr: any) {
    throw {
      error: 'NETWORK_ERROR',
      message: networkErr.message || 'Unable to connect to security gateway.',
      status: 0
    } as ApiError;
  }

  // Check 401 Unauthorized (Expired / Revoked session)
  if (response.status === 401) {
    localStorage.removeItem('cyberguard_token');
    localStorage.removeItem('cyberguard_user');
    if (onUnauthorizedCallback) {
      onUnauthorizedCallback();
    }
    // Only redirect if we are in a browser context and not already on /login
    if (typeof window !== 'undefined' && !window.location.pathname.startsWith('/login')) {
      window.location.href = '/login?expired=true';
    }
    const errData = await response.json().catch(() => ({}));
    throw {
      error: errData.error || 'UNAUTHORIZED',
      message: errData.message || 'Session expired or invalidated. Please sign in again.',
      status: 401
    } as ApiError;
  }

  // Check 403 Forbidden (Role mismatch, Account Locked, or Cross-Tenant boundary violation)
  if (response.status === 403) {
    const errData = await response.json().catch(() => ({}));
    if (onForbiddenCallback) {
      onForbiddenCallback(errData);
    }
    // If account was locked by administrator, redirect to login with locked notice
    if (errData.error === 'ACCOUNT_LOCKED' && typeof window !== 'undefined' && !window.location.pathname.startsWith('/login')) {
      localStorage.removeItem('cyberguard_token');
      localStorage.removeItem('cyberguard_user');
      window.location.href = '/login?locked=true';
    }
    throw {
      error: errData.error || 'FORBIDDEN',
      message: errData.message || 'Access denied by institutional security policy.',
      status: 403
    } as ApiError;
  }

  // Parse payload
  let data: any = {};
  const contentType = response.headers.get('content-type');
  if (contentType && contentType.includes('application/json')) {
    data = await response.json().catch(() => ({}));
  }

  if (!response.ok) {
    throw {
      error: data.error || 'REQUEST_FAILED',
      message: data.message || `Request failed with HTTP status ${response.status}`,
      status: response.status
    } as ApiError;
  }

  return data as T;
}

export const api = {
  get: <T = any>(endpoint: string, options?: RequestInit) =>
    apiClient<T>(endpoint, { method: 'GET', ...options }),

  post: <T = any>(endpoint: string, body?: any, options?: RequestInit) =>
    apiClient<T>(endpoint, {
      method: 'POST',
      body: body !== undefined ? JSON.stringify(body) : undefined,
      ...options
    }),

  put: <T = any>(endpoint: string, body?: any, options?: RequestInit) =>
    apiClient<T>(endpoint, {
      method: 'PUT',
      body: body !== undefined ? JSON.stringify(body) : undefined,
      ...options
    }),

  delete: <T = any>(endpoint: string, options?: RequestInit) =>
    apiClient<T>(endpoint, { method: 'DELETE', ...options })
};

