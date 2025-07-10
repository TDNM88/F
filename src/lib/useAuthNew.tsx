'use client'

import { useState, useEffect, createContext, useContext, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { User } from '@/types/auth';

export type AuthContextType = {
  user: User | null;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<{ success: boolean; message?: string }>;
  logout: () => Promise<void>;
  isAuthenticated: () => boolean;
  isAdmin: () => boolean;
  refreshUser: () => Promise<void>;
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

// Cache user data with a timestamp in localStorage
const AUTH_CACHE_KEY = 'auth_user_cache';
const CACHE_DURATION = 7 * 24 * 60 * 60 * 1000; // 7 days cache duration (matching cookie expiration)

// Helper functions to get/set auth cache
function getAuthCache(): { data: User | null; timestamp: number } | null {
  if (typeof window === 'undefined') return null;
  
  try {
    const cached = localStorage.getItem(AUTH_CACHE_KEY);
    return cached ? JSON.parse(cached) : null;
  } catch (e) {
    console.error('Failed to parse auth cache:', e);
    return null;
  }
}

function setAuthCache(userData: User | null): void {
  if (typeof window === 'undefined') return;
  
  try {
    if (userData) {
      localStorage.setItem(AUTH_CACHE_KEY, JSON.stringify({
        data: userData,
        timestamp: Date.now()
      }));
    } else {
      localStorage.removeItem(AUTH_CACHE_KEY);
    }
  } catch (e) {
    console.error('Failed to set auth cache:', e);
  }
}

function useAuthStandalone(): AuthContextType {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();

  // Check authentication status
  const checkAuth = useCallback(async (force = false) => {
    try {
      const now = Date.now();
      
      // Check cache first
      const cachedUser = getAuthCache();
      if (cachedUser && (now - cachedUser.timestamp < CACHE_DURATION) && !force) {
        setUser(cachedUser.data);
        setIsLoading(false);
        return;
      }

      setIsLoading(true);
      
      // Fetch user data from /api/auth/me
      const response = await fetch('/api/auth/me', {
        credentials: 'same-origin',
        headers: {
          'Cache-Control': 'no-cache',
        },
      });

      if (response.ok) {
        const data = await response.json();
        if (data.success && data.user) {
          // Update cache
          setAuthCache(data.user);
          setUser(data.user);
        } else {
          // Clear cache if not authenticated
          setAuthCache(null);
          setUser(null);
        }
      } else {
        // Clear cache on error
        setAuthCache(null);
        setUser(null);
      }
    } catch (error) {
      console.error('Auth check failed:', error);
      setAuthCache(null);
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Login function
  const login = async (username: string, password: string) => {
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
        credentials: 'same-origin',
      });

      const data = await response.json();
      
      if (response.ok && data.user) {
        // Set user in state and localStorage immediately
        setUser(data.user);
        setAuthCache(data.user);
      } else if (response.ok) {
        // Force refresh user data after successful login if no user data returned
        await checkAuth(true);
      }
      
      return {
        success: response.ok,
        message: data.message
      };
    } catch (error) {
      console.error('Login failed:', error);
      return {
        success: false,
        message: 'Đã xảy ra lỗi khi đăng nhập'
      };
    }
  };

  // Logout function
  const logout = async () => {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'same-origin',
      });
      
      // Clear cache and state
      setAuthCache(null);
      setUser(null);
      
      // Redirect to login page
      router.push('/login');
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  // Check if user is authenticated
  const isAuthenticated = useCallback(() => {
    return !!user;
  }, [user]);

  // Check if user is admin
  const isAdmin = useCallback(() => {
    return user?.role === 'admin';
  }, [user]);

  // Initial auth check
  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  return {
    user,
    isLoading,
    login,
    logout,
    isAuthenticated,
    isAdmin,
    refreshUser: () => checkAuth(true),
  };
}

// AuthProvider component
type AuthProviderProps = {
  children: React.ReactNode;
};

export function AuthProvider({ children }: AuthProviderProps) {
  const auth = useAuthStandalone();
  return <AuthContext.Provider value={auth}>{children}</AuthContext.Provider>;
}

export default AuthProvider;
