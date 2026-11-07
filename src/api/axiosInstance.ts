import axios from 'axios';
import type { AxiosError, InternalAxiosRequestConfig } from 'axios';
import { clearStoredOrgId, setStoredOrgId } from '@/lib/authStorage';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8080/erp/api';

export const api = axios.create({
  baseURL: API_BASE,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const authClient = axios.create({
  baseURL: API_BASE,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

interface RefreshResponse {
  message: string;
  orgId: number | null;
  status: string;
}

interface RetriableRequestConfig extends InternalAxiosRequestConfig {
  _retry?: boolean;
}

/**
 * Single-flight refresh token request.
 *
 * While a `/v1/refresh` call is in flight, every caller shares the same promise
 * so that multiple simultaneous 401s trigger only one refresh request. Once the
 * refresh settles (success or failure) the promise is cleared so the next expired
 * session can refresh again.
 */
let refreshPromise: Promise<number | null> | null = null;

export function refreshSession(): Promise<number | null> {
  if (!refreshPromise) {
    refreshPromise = authClient
      .post<RefreshResponse>('/v1/refresh')
      .then(({ data }) => {
        if (data.orgId != null) {
          setStoredOrgId(data.orgId);
        }
        return data.orgId ?? null;
      })
      .finally(() => {
        refreshPromise = null;
      });
  }

  return refreshPromise;
}

function isAuthRequest(url: string | undefined): boolean {
  if (!url) return false;
  return ['/v1/login', '/v1/refresh', '/v1/logout'].some((path) =>
    url.includes(path)
  );
}

function isRetried(config: InternalAxiosRequestConfig | undefined): boolean {
  return !!(config as RetriableRequestConfig | undefined)?._retry;
}

function statusOf(err: AxiosError): number | undefined {
  return err.response?.status ?? err.status;
}

function isUnauthorized(err: AxiosError): boolean {
  return statusOf(err) === 401;
}

/**
 * The JWT filter rejects expired tokens before Spring MVC runs, and those
 * responses do not always carry the CORS headers the browser needs to expose
 * them. In that case axios reports a network error with no response at all,
 * even though the request actually failed with a 401. Treat that opaque
 * failure as a possible auth failure and let the refresh attempt decide.
 */
function isOpaqueAuthFailure(err: AxiosError): boolean {
  return !err.response && err.code === 'ERR_NETWORK';
}

function signOut(): void {
  clearStoredOrgId();

  if (typeof window === 'undefined') return;
  if (window.location.pathname !== '/login') {
    window.location.assign('/login');
  }
}

api.interceptors.response.use(
  (res) => res,
  async (err: AxiosError) => {
    const original = err.config as RetriableRequestConfig | undefined;

    if (!original || axios.isCancel(err) || isAuthRequest(original.url)) {
      return Promise.reject(err);
    }

    const unauthorized = isUnauthorized(err);
    if (!unauthorized && !isOpaqueAuthFailure(err)) {
      return Promise.reject(err);
    }

    if (isRetried(original)) {
      if (unauthorized) signOut();
      return Promise.reject(err);
    }

    original._retry = true;

    try {
      await refreshSession();
    } catch (refreshError) {
      if (isUnauthorized(refreshError as AxiosError)) {
        signOut();
      }
      return Promise.reject(err);
    }
    return api(original);
  }
);

export default api;
