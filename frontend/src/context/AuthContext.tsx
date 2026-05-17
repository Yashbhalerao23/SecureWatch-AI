import React, { createContext, useContext, useEffect, useState } from 'react';
import { UserProfile } from '../types';
import { api } from '../lib/axios';

const AUTH_TOKEN_KEY = 'soc_auth_token';
const REFRESH_TOKEN_KEY = 'soc_refresh_token';

interface AuthContextValue {
  user: UserProfile | null;
  loading: boolean;
  refreshUser: () => Promise<void>;
  refreshUserWithToken: (overrideToken: string) => Promise<void>;
  setAuthToken: (token: string | null) => void;
  setRefreshToken: (token: string | null) => void;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [token, setToken] = useState<string | null>(() => {
    return typeof window !== 'undefined' ? localStorage.getItem(AUTH_TOKEN_KEY) : null;
  });

  const setAuthToken = (nextToken: string | null) => {
    setToken(nextToken);

    if (!nextToken) {
      delete api.defaults.headers.common.Authorization;
      if (typeof window !== 'undefined') {
        localStorage.removeItem(AUTH_TOKEN_KEY);
        localStorage.removeItem(REFRESH_TOKEN_KEY);
      }
      return;
    }

    api.defaults.headers.common.Authorization = `Bearer ${nextToken}`;
    if (typeof window !== 'undefined') {
      localStorage.setItem(AUTH_TOKEN_KEY, nextToken);
    }
  };

  const setRefreshToken = (nextToken: string | null) => {
    if (typeof window === 'undefined') return;
    if (nextToken) {
      localStorage.setItem(REFRESH_TOKEN_KEY, nextToken);
    } else {
      localStorage.removeItem(REFRESH_TOKEN_KEY);
    }
  };

  const refreshUser = async () => {
    setLoading(true);
    try {
      // Ensure the request uses the latest token
      const response = await api.get<UserProfile>('/users/me/');
      setUser(response.data);
    } catch (error) {
      setUser(null);
      setAuthToken(null);
    } finally {
      setLoading(false);
    }
  };

  const refreshUserWithToken = async (overrideToken: string) => {
    setLoading(true);
    try {
      api.defaults.headers.common.Authorization = `Bearer ${overrideToken}`;
      const response = await api.get<UserProfile>('/users/me/');
      setUser(response.data);
    } catch (error) {
      setUser(null);
    } finally {
      setLoading(false);
    }
  };



  const logout = async () => {
    try {
      await api.post('/auth/logout/');
    } catch (error) {
      console.warn('Logout failed, clearing local auth state', error);
    }

    setAuthToken(null);
    setUser(null);
  };

  useEffect(() => {
    if (!token) {
      setUser(null);
      setLoading(false);
      return;
    }

    api.defaults.headers.common.Authorization = `Bearer ${token}`;
    refreshUser();
  }, [token]);

  return (
    <AuthContext.Provider value={{ user, loading, refreshUser, refreshUserWithToken, setAuthToken, setRefreshToken, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used inside AuthProvider');
  }
  return context;
}
