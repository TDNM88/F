'use client'

import { useState, useEffect, createContext, useContext, useCallback, useRef } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { User } from '@/types/auth';

// Export interface sử dụng type keyword để đảm bảo Next.js/TypeScript hiểu và xử lý chính xác
export type AuthContextType = {
  user: User | null;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<{ success: boolean; message?: string }>;
  logout: () => Promise<void>;
  isAuthenticated: () => boolean;
  isAdmin: () => boolean;
  refreshUser: () => Promise<void>;
}

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
const CACHE_DURATION = 30 * 24 * 60 * 60 * 1000; // 30 days cache duration (longer than cookie expiration for better UX)

// Helper functions to get/set auth cache
function getAuthCache(): { data: User | null; timestamp: number } | null {
  if (typeof window === 'undefined') return null;
  
  try {
    const cached = localStorage.getItem(AUTH_CACHE_KEY);
    if (!cached) return null;
    
    const parsedCache = JSON.parse(cached);
    // Log cache details for debugging
    console.debug('Auth cache found', { 
      created: new Date(parsedCache.timestamp).toLocaleString(),
      expiresIn: Math.round((parsedCache.timestamp + CACHE_DURATION - Date.now()) / (1000 * 60 * 60 * 24)) + ' days'
    });
    
    return parsedCache;
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
  const authCheckInProgressRef = useRef<boolean>(false);
  const router = useRouter();
  const pathname = usePathname();
  const lastPathRef = useRef<string | null>(null);

  // Check authentication status with improved resilience
  const checkAuth = useCallback(async (force = false) => {
    // Prevent multiple simultaneous auth checks
    if (authCheckInProgressRef.current) {
      console.debug('Auth check already in progress, skipping duplicate request');
      return;
    }
    
    try {
      authCheckInProgressRef.current = true;
      const now = Date.now();
      
      // Throttle frequent checks (except when forced)
      if (!force && lastChecked > 0 && (now - lastChecked) < 5000) {
        console.debug('Auth check throttled', { timeSinceLastCheck: now - lastChecked });
        authCheckInProgressRef.current = false;
        return; // Avoid checking more than once every 5 seconds
      }

      // Always try cache first, even during forced refreshes
      // This ensures we have something to display immediately
      const cachedUser = getAuthCache();
      if (cachedUser && cachedUser.data) {
        // Always set user from cache first if available
        setUser(cachedUser.data);
        setIsLoading(false);
        
        // If cache is fresh and not forcing refresh, we can return early
        if (!force && (now - cachedUser.timestamp < CACHE_DURATION)) {
          console.debug('Using cached user data', { user: cachedUser.data.username });
          setLastChecked(now);
          authCheckInProgressRef.current = false;
          return;
        }
      }

      console.debug('Checking authentication with server');
      if (force) {
        setIsLoading(true);
      }
      
      // Fetch user data from /api/auth/me with timeout to handle network issues
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000); // 8 second timeout
      
      try {
        const response = await fetch('/api/auth/me', {
          credentials: 'include', // Explicitly include credentials for all requests
          headers: {
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
          },
          signal: controller.signal,
          // Force timestamp to prevent browser caching
          cache: 'no-store'
        });

        clearTimeout(timeoutId);

        if (response.ok) {
          const data = await response.json();
          if (data.success && data.user) {
            console.debug('Successfully authenticated with server', { user: data.user.username });
            // Update cache
            setAuthCache(data.user);
            setUser(data.user);
          } else {
            console.debug('Server returned no auth error but no user data');
            // Only clear if we're doing a force refresh or don't have cache
            if (force || !cachedUser) {
              setAuthCache(null);
              setUser(null);
            } else {
              // Keep using cached data on weird server responses
              console.debug('Keeping cached user data due to unusual server response');
            }
          }
        } else {
          // For explicit auth errors (401, 403), clear cache
          if (response.status === 401 || response.status === 403) {
            console.debug('Auth failed with status:', response.status);
            setAuthCache(null);
            setUser(null);
          } else {
            // For other errors (500, network issues, etc.), KEEP existing state
            console.error('Auth check failed with status:', response.status);
            
            // If we have cached data, keep using it during server errors
            if (cachedUser) {
              console.debug('Keeping cached user data during server error');
              // Refresh cache timestamp to avoid immediate re-requests
              setAuthCache(cachedUser.data);
              setUser(cachedUser.data);
            }
          }
        }
      } catch (error) {
        console.error('Error checking auth status:', error);
        clearTimeout(timeoutId);
        
        // ALWAYS keep existing user state on network errors
        if (cachedUser) {
          console.debug('Network error during auth check, keeping cached user data');
          // Refresh cache timestamp to avoid immediate re-requests
          setAuthCache(cachedUser.data);
          setUser(cachedUser.data);
        }
      }
      
      setIsLoading(false);
      setLastChecked(now);
    } catch (e) {
      console.error('Auth check error:', e);
      setIsLoading(false);
    } finally {
      authCheckInProgressRef.current = false;
    }
  }, [lastChecked]);  // Added lastChecked dependency

  // Login function
  const login = async (username: string, password: string) => {
    try {
      console.debug('Attempting login for user:', username);
      
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache',
          'Pragma': 'no-cache'
        },
        body: JSON.stringify({ username, password }),
        credentials: 'include', // Explicitly include credentials
        cache: 'no-store',
      });

      const data = await response.json();
      
      if (response.ok && data.user) {
        console.debug('Login successful, user data received');
        // Set user in state and localStorage immediately
        setUser(data.user);
        setAuthCache(data.user);
        setLastChecked(Date.now());
        
        // Reset path tracking to prevent immediate redirects
        lastPathRef.current = pathname;
      } else if (response.ok) {
        console.debug('Login successful but no user data, fetching user data');
        // Force refresh user data after successful login if no user data returned
        await checkAuth(true);
      } else {
        console.error('Login failed with status:', response.status);
      }
      
      return {
        success: response.ok,
        message: data.message
      };
    } catch (error) {
      console.error('Login failed with error:', error);
      return {
        success: false,
        message: 'Đã xảy ra lỗi khi đăng nhập. Vui lòng thử lại sau.'
      };
    }
  };

  // Logout function
  const logout = async () => {
    try {
      console.debug('Logging out user');
      
      // Clear client-side auth state immediately
      setAuthCache(null);
      setUser(null);
      setLastChecked(0);
      
      // Then attempt server logout
      await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Cache-Control': 'no-cache',
          'Pragma': 'no-cache'
        },
        cache: 'no-store',
      });
      
      // Redirect to login page
      router.push('/login');
    } catch (error) {
      console.error('Logout server request failed:', error);
      // We already cleared local state and cache above
      // so just redirect to login page
      router.push('/login');
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

  // Enhanced auth check on initial load and pathname changes
  useEffect(() => {
    if (pathname !== lastPathRef.current) {
      console.debug('Path changed from', lastPathRef.current, 'to', pathname);
      lastPathRef.current = pathname;
      
      // Only do a soft check (using cache if available) on navigation
      checkAuth(false);
    }
    
    // Initial check - prioritize cache then verify
    if (!lastChecked) {
      checkAuth(false);
    }
    
    // Setup an interval to periodically check auth status in background
    // This ensures session remains valid during long periods of inactivity
    const intervalId = setInterval(() => {
      // Only do a background refresh if the last check was more than 10 minutes ago
      // and user is still in the application (document is visible)
      const now = Date.now();
      if (now - lastChecked > 10 * 60 * 1000 && document.visibilityState === 'visible') {
        console.debug('Performing periodic background auth check');
        checkAuth(false);
      }
    }, 15 * 60 * 1000); // Check every 15 minutes
    
    // Also check auth when tab becomes visible again
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        const now = Date.now();
        if (now - lastChecked > 5 * 60 * 1000) {
          console.debug('Tab became visible, checking auth status');
          checkAuth(false);
        }
      }
    };
    
    document.addEventListener('visibilitychange', handleVisibilityChange);
    
    return () => {
      clearInterval(intervalId);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [checkAuth, pathname, lastChecked]);

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
    const isPublic = publicPaths.some(p => 
      pathname === p || 
      pathname?.startsWith(`${p}/`)
    );
    
    const isSystemPath = 
      pathname?.startsWith('/_next/') ||
      pathname?.startsWith('/api/') ||
      pathname?.includes('favicon.ico');
      
    return !isPublic && !isSystemPath;
  }, [pathname]);

  // Auto redirect to login if on protected page without auth
  useEffect(() => {
    const handleAuthRedirect = async () => {
      // Only proceed if:
      // 1. We're not loading auth state
      // 2. User is NOT authenticated
      // 3. Current page requires authentication
      // 4. We're not already on the login page
      // 5. We've already done at least one auth check
      
      console.debug('Auth state:', {
        isLoading, 
        isAuthenticated: !!user, 
        requiresAuth: requiresAuth(),
        pathname,
        lastChecked
      });
      
      if (!isLoading && !user && requiresAuth() && pathname !== '/login' && lastChecked > 0) {
        console.debug('Redirecting unauthenticated user from protected page');
        // Build the return URL
        const returnUrl = pathname || '/';
        router.push(`/login?returnUrl=${encodeURIComponent(returnUrl)}`);
      }
    };
    
    // Add a small delay before redirect to avoid flash during initial load
    // This gives time for the auth check to complete
    const timeoutId = setTimeout(() => {
      handleAuthRedirect();
    }, 300);
    
    return () => clearTimeout(timeoutId);
  }, [isLoading, user, pathname, router, requiresAuth, lastChecked]);

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
