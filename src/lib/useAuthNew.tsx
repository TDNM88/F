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
        // Log cookie status from document.cookie (if in browser)
        if (typeof document !== 'undefined') {
          console.debug('Cookie status before fetch:', {
            hasCookies: document.cookie.length > 0,
            cookieLength: document.cookie.length,
            hasTokenCookie: document.cookie.includes('token='),
          });
        }
        
        console.debug('Fetching user from /api/auth/me');
        
        const response = await fetch('/api/auth/me', {
          method: 'GET',
          credentials: 'include', // Explicitly include credentials for all requests
          headers: {
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Accept': 'application/json'
          },
          signal: controller.signal,
          // Force timestamp to prevent browser caching
          cache: 'no-store',
          mode: 'cors' // Ensure CORS is handled correctly
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
    setIsLoading(true);
    try {
      console.debug('Attempting login for user:', username);
      
      // Kiểm tra cookie hiện tại trước khi đăng nhập
      if (typeof document !== 'undefined') {
        console.debug('Cookie state before login:', { 
          hasCookies: document.cookie.length > 0,
          cookieLength: document.cookie.length,
          cookies: document.cookie
        });
      }
      
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
      if (data.success) {
        console.debug('Login successful:', data);
        // Update cache
        setAuthCache(data.user);
        setUser(data.user);
        return { success: true, message: 'Đăng nhập thành công' };
      } else {
        console.debug('Login failed:', data);
        return { success: false, message: 'Đăng nhập thất bại' };
      }
    } catch (error) {
      console.error('Login error:', error);
      return { success: false, message: 'Có lỗi xảy ra khi đăng nhập' };
    } finally {
      setIsLoading(false);
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
  const requiresAuth = (path: string): boolean => {
    // Public paths that don't require authentication
    const publicPaths = [
      '/',
      '/login',
      '/register',
      '/forgot-password',
      '/reset-password'
    ];

    // Public paths that start with these prefixes
    const publicPathPrefixes = [
      '/api/public',
      '/_next',
      '/favicon',
      '/static',
    ];

    // Check if the path exactly matches a public path
    const isExactPublicPath = publicPaths.includes(path);
    
    // Check if the path starts with a public prefix
    const hasPublicPrefix = publicPathPrefixes.some(prefix => path.startsWith(prefix));
    
    // Special handling for root and sub-paths
    const isPublicSubPath = publicPaths.some(publicPath => {
      // Skip the root path for this check to prevent everything being public
      if (publicPath === '/') return false;
      return path.startsWith(`${publicPath}/`);
    });

    const isPublicPath = isExactPublicPath || hasPublicPrefix || isPublicSubPath;

    console.debug('requiresAuth check:', { 
      path, 
      isPublicPath, 
      isExactPublicPath, 
      hasPublicPrefix, 
      isPublicSubPath 
    });
    
    return !isPublicPath;
  };

  // Function to handle auth redirects based on path and auth state
  const handleAuthRedirect = useCallback((path: string): void => {
    console.debug('handleAuthRedirect called for path:', path);
    
    // Prevent redirect loops
    if (path === lastPathRef.current) {
      console.debug('Skipping redirect - same as last path');
      return;
    }
    
    // Update last path reference
    lastPathRef.current = path;
    
    const isPathProtected = requiresAuth(path);
    const isUserAuthenticated = !!user;
    const isAuthLoading = isLoading;
    
    console.debug('Auth redirect check:', { 
      path, 
      isPathProtected, 
      isUserAuthenticated,
      isAuthLoading,
      hasUser: !!user,
      username: user?.username || null,
      lastChecked
    });
    
    // Don't redirect while still loading auth state
    if (isAuthLoading) {
      console.debug('Skipping redirect - auth state still loading');
      return;
    }
    
    if (isPathProtected && !isUserAuthenticated && lastChecked > 0) {
      console.debug('Redirecting unauthenticated user from protected page');
      // Build the return URL
      const returnUrl = path || '/';
      router.push(`/login?returnUrl=${encodeURIComponent(returnUrl)}`);
    } else if (path === '/login' && isUserAuthenticated) {
      console.debug('Redirecting authenticated user from login page');
      router.push('/');
    }
  }, [user, isLoading, router, requiresAuth, lastChecked]);
  
  // Auto redirect to login if on protected page without auth
  useEffect(() => {
    if (!pathname) return;
    
    // Add a small delay before redirect to avoid flash during initial load
    // This gives time for the auth check to complete
    const timeoutId = setTimeout(() => {
      handleAuthRedirect(pathname);
    }, 300);
    
    return () => clearTimeout(timeoutId);
  }, [pathname, handleAuthRedirect]);

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
