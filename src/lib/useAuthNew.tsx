'use client'

import { useState, useEffect, useRef, useCallback, useContext, createContext } from 'react';
import { useRouter } from 'next/navigation';
import { usePathname } from 'next/navigation';
import { User } from '@/types/auth';

// Storage keys
const USER_STORAGE_KEY = 'auth_user';
const LAST_CHECKED_KEY = 'auth_last_checked';

// Helper function để kiểm soát logging
const debugLog = (message: string, data?: any) => {
  if (process.env.DEBUG_AUTH === 'true' || process.env.NODE_ENV !== 'production') {
    console.debug(`[Auth Client] ${message}`, data);
  }
};

// TypesScript hiểu và xử lý chính xác
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
    debugLog('Auth cache found', { 
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

// Standalone auth hook for use in AuthProvider
export function useAuthStandalone() {
  // State
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [lastChecked, setLastChecked] = useState<number>(0);
  
  // Refs for auth status checks
  const checkIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const lastPathRef = useRef<string>('');
  const lastRedirectTimeRef = useRef<number>(0); // Lưu thời gian chuyển hướng gần nhất để tránh loops
  const router = useRouter();
  const pathname = usePathname();

  // Check authentication status with improved resilience
  const checkAuth = useCallback(async (force = false) => {
    const currentTime = new Date().getTime();
    const cacheTimeout = 5 * 60 * 1000; // 5 minutes
    
    // Skip check if not forced and checked recently
    if (!force && lastChecked && currentTime - lastChecked < cacheTimeout) {
      debugLog('Skipping auth check - Recent check exists', {
        timeSinceLastCheck: Math.floor((currentTime - lastChecked) / 1000) + 's'
      });
      return;
    }

    try {
      // Show loading state only for initial check
      const isInitialCheck = !lastChecked;
      if (isInitialCheck) {
        setIsLoading(true);
        debugLog('Initial auth check starting');
      } else if (force) {
        debugLog('Forced auth check starting');
      }
      
      // Đảm bảo gửi credentials và tránh cache
      const response = await fetch('/api/auth/me', { 
        credentials: 'include', 
        headers: { 
          'Cache-Control': 'no-cache',
          'Pragma': 'no-cache'
        }
      });
      
      const data = await response.json();
      
      if (response.ok && data.success) {
        debugLog('User authenticated from API', {
          role: data.user?.role,
          userId: data.user?.id ? String(data.user.id).substring(0, 4) + '...' : null
        });
        
        setUser(data.user);
        // Store user data in localStorage with timestamp for caching
        localStorage.setItem(
          USER_STORAGE_KEY, 
          JSON.stringify({
            data: data.user,
            timestamp: currentTime
          })
        );
      } else {
        // Clear user data on auth failure
        debugLog('User not authenticated from API', {
          status: response.status,
          error: data.message || 'Authentication failed'
        });
        setUser(null);
        localStorage.removeItem(USER_STORAGE_KEY);
      }
    } catch (error) {
      console.error('Error checking auth status:', 
        error instanceof Error ? error.message : 'Unknown error');
      // Don't clear user on network errors to preserve offline experience
    } finally {
      setIsLoading(false);
      setLastChecked(currentTime);
      localStorage.setItem(LAST_CHECKED_KEY, currentTime.toString());
    }
  }, [lastChecked]);

  // Login function
  const login = async (username: string, password: string) => {
    setIsLoading(true);
    try {
      debugLog('Attempting login for user:', username);
      
      // Kiểm tra cookie hiện tại trước khi đăng nhập
      if (typeof document !== 'undefined') {
        debugLog('Cookie state before login:', { 
          hasCookies: document.cookie.length > 0,
          cookieLength: document.cookie.length,
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
        debugLog('Login successful:', data);
        // Update cache
        setAuthCache(data.user);
        setUser(data.user);
        return { success: true, message: 'Đăng nhập thành công' };
      } else {
        debugLog('Login failed:', data);
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
      debugLog('Logging out user');
      
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

  // Check if current path requires authentication
  const requiresAuth = useCallback((path: string): boolean => {
    if (!path) return false;
    
    // Public paths - mở rộng danh sách
    const publicPaths = [
      '/',
      '/login', 
      '/auth/login',
      '/register', 
      '/auth/register',
      '/static',
      '/public',
      '/api',
      '/favicon.ico',
      '/_next',
      '/images',
      '/assets'
    ];
    
    // Check if path is public
    const isPublic = publicPaths.some(p => path === p || path.startsWith(p));
    
    // Thêm debug log
    if (!isPublic) {
      debugLog('Path requires auth', { path });
    }
    
    return !isPublic;
  }, []);

  // Handle redirect based on auth status and path
  const handleAuthRedirect = useCallback((path: string): void => {
    // Don't redirect if no path
    if (!path) return;
    
    // Don't redirect when loading
    if (isLoading) {
      debugLog('Skipping redirect - Auth still loading', { path });
      return;
    }
    
    // Tránh chuyển hướng đến cùng một path liên tục
    if (path === lastPathRef.current) {
      debugLog('Skipping redirect - Already redirected to this path', { path });
      return;
    }
    
    // Log ít thông tin hơn để tránh lộ dữ liệu
    debugLog('Checking auth redirect', { 
      path, 
      isAuthenticated: !!user,
      lastRedirectTime: new Date().getTime() - lastRedirectTimeRef.current
    });

    // Kiểm tra nếu đã chuyển hướng gần đây để tránh redirect loops
    const redirectCooldown = 1000; // 1 giây
    const now = new Date().getTime();
    if (now - lastRedirectTimeRef.current < redirectCooldown) {
      debugLog('Redirect blocked - Too soon after previous redirect', {
        msSinceLastRedirect: now - lastRedirectTimeRef.current
      });
      return;
    }

    // Remember current path to prevent redirect loops
    lastPathRef.current = path;

    // Path checks với các route nên kiểm tra một cách chi tiết hơn
    const isLoginPath = path === '/login' || path === '/auth/login';
    const isRegisterPath = path === '/register' || path === '/auth/register';
    const isAuthPath = isLoginPath || isRegisterPath || path.startsWith('/auth/');
    const isPublicPath = isAuthPath || path === '/' || path.startsWith('/static/');
    const needsRedirect = requiresAuth(path) && !user;

    // Redirect login/register to home if already authenticated
    if (user && isAuthPath) {
      debugLog('Redirecting to home - Already authenticated user on auth page');
      router.push('/');
      lastRedirectTimeRef.current = now; // Cập nhật thời gian chuyển hướng
      return;
    }

    // Redirect protected pages to login if not authenticated
    if (needsRedirect) {
      debugLog('Redirecting to login - Authentication required');
      router.push('/login');
      lastRedirectTimeRef.current = now; // Cập nhật thời gian chuyển hướng
      return;
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
