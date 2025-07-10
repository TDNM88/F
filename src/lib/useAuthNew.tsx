'use client'

import { useState, useEffect, createContext, useContext, useCallback } from 'react';
import { useRouter, usePathname } from 'next/navigation';
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
  const [lastChecked, setLastChecked] = useState<number>(0);
  const router = useRouter();
  const pathname = usePathname();

  // Check authentication status
  const checkAuth = useCallback(async (force = false) => {
    try {
      const now = Date.now();
      
      // Throttle frequent checks (except when forced)
      if (!force && lastChecked > 0 && (now - lastChecked) < 5000) {
        return; // Avoid checking more than once every 5 seconds
      }

      // Check cache first
      const cachedUser = getAuthCache();
      if (cachedUser && (now - cachedUser.timestamp < CACHE_DURATION) && !force) {
        setUser(cachedUser.data);
        setIsLoading(false);
        setLastChecked(now);
        return;
      }

      setIsLoading(true);
      
      // Fetch user data from /api/auth/me with timeout to handle network issues
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout
      
      try {
        const response = await fetch('/api/auth/me', {
          credentials: 'same-origin',
          headers: {
            'Cache-Control': 'no-cache',
          },
          signal: controller.signal
        });

        clearTimeout(timeoutId);

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
          // For auth errors (401, 403), clear cache
          if (response.status === 401 || response.status === 403) {
            setAuthCache(null);
            setUser(null);
          } else {
            // For other errors (500, etc.), keep existing state if we have it
            console.error('Auth check failed with status:', response.status);
            
            // If we have cached data, keep using it during server errors
            if (cachedUser && !force) {
              setUser(cachedUser.data);
            }
          }
        }
      } catch (fetchError) {
        clearTimeout(timeoutId);
        console.error('Fetch error:', fetchError);
        
        // Network error - keep existing auth state if we have it
        if (cachedUser && !force) {
          console.log('Using cached user data during network error');
          setUser(cachedUser.data);
        }
      }
    } catch (error) {
      console.error('Auth check failed:', error);
      // Don't clear cache on general errors - only clear on explicit auth failures
    } finally {
      setIsLoading(false);
      setLastChecked(Date.now());
    }
  }, [lastChecked]);  // Added lastChecked dependency

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
      setLastChecked(0);
      
      // Redirect to login page
      router.push('/login');
    } catch (error) {
      console.error('Logout failed:', error);
      // Still clear local state and cache even if server logout fails
      setAuthCache(null);
      setUser(null);
      setLastChecked(0);
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

  // Auth check on initial load and pathname changes
  useEffect(() => {
    // Initial auth check and when pathname changes
    checkAuth();
    
    // Setup an interval to periodically check auth status in background
    // This ensures session remains valid during long periods of inactivity
    const intervalId = setInterval(() => {
      // Only do a background refresh if the last check was more than 5 minutes ago
      const now = Date.now();
      if (now - lastChecked > 5 * 60 * 1000) {
        checkAuth();
      }
    }, 10 * 60 * 1000); // Check every 10 minutes
    
    return () => clearInterval(intervalId);
  }, [checkAuth, pathname]); // Added pathname dependency

  // Expose a way to check if we're on a protected page that requires auth
  const requiresAuth = useCallback(() => {
    // List of public paths that don't require authentication
    const publicPaths = [
      '/',
      '/login', 
      '/register', 
      '/auth/login', 
      '/auth/register',
      '/forgot-password',
      '/reset-password'
    ];

    // Check if the current path is public
    return !publicPaths.some(p => 
      pathname === p || 
      pathname?.startsWith(`${p}/`) ||
      pathname?.startsWith('/_next/') ||
      pathname?.startsWith('/api/') ||
      pathname?.includes('favicon.ico')
    );
  }, [pathname]);

  // Auto redirect to login if on protected page without auth
  useEffect(() => {
    const handleAuthRedirect = async () => {
      // Only proceed if:
      // 1. We're not loading auth state
      // 2. User is not authenticated
      // 3. Current page requires authentication
      // 4. We're not already on the login page
      if (!isLoading && !user && requiresAuth() && pathname !== '/login') {
        // Build the return URL
        const returnUrl = pathname || '/';
        router.push(`/login?returnUrl=${encodeURIComponent(returnUrl)}`);
      }
    };
    
    handleAuthRedirect();
  }, [isLoading, user, pathname, router, requiresAuth]);

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
