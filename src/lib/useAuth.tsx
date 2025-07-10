"use client"

import React from 'react';
import { createContext, useContext, useState, useEffect, ReactNode, useCallback } from 'react';

type User = {
  id: string;
  username: string;
  role: string;
  avatar?: string;
  balance: {
    available: number;
    frozen: number;
  };
  bank?: {
    name: string;
    accountNumber: string;
    accountHolder: string;
  };
  verification?: {
    verified: boolean;
    cccdFront: string;
    cccdBack: string;
  };
  status?: {
    active: boolean;
    betLocked: boolean;
    withdrawLocked: boolean;
  };
  createdAt?: string;
  lastLogin?: string;
};

type AuthContextType = {
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

// Cache user data with a timestamp and token
let cachedUser: { 
  data: User | null; 
  timestamp: number;
  token: string | null;
} | null = null;

const CACHE_DURATION = 30 * 60 * 1000; // 30 minutes cache duration
const TOKEN_REFRESH_THRESHOLD = 5 * 60 * 1000; // 5 minutes before token expiry

function useAuthStandalone(): AuthContextType {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [lastChecked, setLastChecked] = useState<number>(0);
  const [isChecking, setIsChecking] = useState(false);

  // Debounce function to prevent rapid consecutive calls
  const debounce = <F extends (...args: any[]) => any>(
    func: F,
    delay: number
  ) => {
    let timeoutId: NodeJS.Timeout;
    return (...args: Parameters<F>) => {
      clearTimeout(timeoutId);
      return new Promise<ReturnType<F>>(resolve => {
        timeoutId = setTimeout(() => {
          resolve(func(...args));
        }, delay);
      });
    };
  };

  // Memoize the checkAuth function with better error handling
  const checkAuth = useCallback(debounce(async (force = false) => {
    // Skip if already checking
    if (isChecking && !force) return;
    
    // Check cache first
    const now = Date.now();
    if (cachedUser && (now - cachedUser.timestamp < CACHE_DURATION) && !force) {
      // If we have a valid cached user and token, use it
      console.log('Using cached user data');
      setUser(cachedUser.data);
      setIsLoading(false);
      
      // If token is about to expire, refresh it in the background
      if (cachedUser.token && (now - cachedUser.timestamp) > (CACHE_DURATION - TOKEN_REFRESH_THRESHOLD)) {
        console.log('Token about to expire, refreshing in background...');
        checkAuth(true).catch(console.error);
      }
      return;
    }

    setIsChecking(true);
    setIsLoading(true);
    
    try {
      console.log('Checking authentication status...');
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 50000); // 5 second timeout
      
      // Get token from storage as fallback
      const token = document.cookie
        .split('; ')
        .find(row => row.startsWith('token='))
        ?.split('=')[1] || null;

      const headers: HeadersInit = {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
      };

      // Only add Authorization header if we have a token
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      const res = await fetch('/api/auth/me', {
        method: 'GET',
        credentials: 'include',
        signal: controller.signal,
        headers
      });
      
      clearTimeout(timeoutId);
      
      console.log('Auth check response status:', res.status);
      
      if (res.ok) {
        const data = await res.json().catch(e => {
          console.error('Error parsing auth response:', e);
          return { success: false };
        });
        
        if (data?.success && data.user) {
          console.log('User authenticated:', data.user.username);
          // Update cache with user data and token
          cachedUser = {
            data: data.user,
            timestamp: Date.now(),
            token: data.token || token // Use new token if provided, otherwise keep existing
          };
          setUser(data.user);
          
          // Update token in cookie if new one was provided
          if (data.token) {
            document.cookie = `token=${data.token}; path=/; max-age=${30 * 24 * 60 * 60}; SameSite=Lax`;
          }
        } else {
          console.log('No valid user data in response');
          // Only clear cache if we're sure the user is not authenticated
          if (res.status === 401) {
            cachedUser = { 
              data: null, 
              timestamp: Date.now(),
              token: null 
            };
            setUser(null);
          }
        }
      } else {
        console.log('Auth check failed with status:', res.status);
        // Only clear cache on 401 Unauthorized
        if (res.status === 401) {
          cachedUser = { 
            data: null, 
            timestamp: Date.now(),
            token: null 
          };
          setUser(null);
        }
      }
    } catch (error) {
      console.error('Auth check failed:', error);
      // Don't update cache on network errors, use the last known good state
      if (error instanceof Error) {
        if (error.name === 'AbortError') {
          console.warn('Auth check timed out');
        } else {
          console.error('Auth check error:', error.message);
        }
      } else {
        console.error('Unknown error during auth check');
      }
    } finally {
      setIsLoading(false);
      setIsChecking(false);
      setLastChecked(Date.now());
    }
  }, 300), [isChecking]); // Only recreate if isChecking changes

  // Initial auth check
  useEffect(() => {
    checkAuth();
    
    // Set up periodic refresh (every 5 minutes)
    const intervalId = setInterval(() => {
      if (document.visibilityState === 'visible') {
        checkAuth();
      }
    }, 5 * 60 * 1000);
    
    // Check auth when window regains focus
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        checkAuth();
      }
    };
    
    document.addEventListener('visibilitychange', handleVisibilityChange);
    
    return () => {
      clearInterval(intervalId);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [checkAuth]);

  const login = async (username: string, password: string) => {
    try {
      console.log('=== Login Attempt Started ===');
      console.log('Username:', username);
      
      // Basic input validation
      if (!username || !password) {
        console.error('Validation failed: Missing username or password');
        return { success: false, message: 'Vui lòng nhập tên đăng nhập và mật khẩu' };
      }

      // Create full URL to ensure it's correct
      const apiUrl = new URL('/api/login', window.location.origin).toString();
      console.log('Sending login request to:', apiUrl);
      
      const startTime = Date.now();
      let res;
      
      try {
        res = await fetch(apiUrl, {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
          },
          body: JSON.stringify({ 
            username: username.trim(), 
            password: password 
          }),
          credentials: 'include',
        });
      } catch (fetchError) {
        console.error('Network error during fetch:', fetchError);
        return { 
          success: false, 
          message: 'Không thể kết nối đến máy chủ. Vui lòng kiểm tra kết nối mạng của bạn.' 
        };
      }
      
      const responseTime = Date.now() - startTime;
      console.log(`Login request completed in ${responseTime}ms with status:`, res.status);
      
      // Check if the response is JSON before trying to parse it
      const contentType = res.headers.get('content-type');
      let data;
      
      if (contentType && contentType.includes('application/json')) {
        try {
          data = await res.json();
          console.log('Login response data:', data);
        } catch (parseError) {
          console.error('Error parsing JSON response:', parseError);
          return { 
            success: false, 
            message: 'Lỗi xử lý phản hồi từ máy chủ' 
          };
        }
      } else {
        const text = await res.text();
        console.error('Non-JSON response received:', text);
        return { 
          success: false, 
          message: 'Phản hồi không hợp lệ từ máy chủ' 
        };
      }
      
      if (res.ok && data?.success) {
        console.log('Login API call successful, verifying authentication...');
        
        // Add a small delay to ensure the cookie is set
        await new Promise(resolve => setTimeout(resolve, 300));
        
        try {
          // Try to get the current user
          console.log('Attempting to fetch current user...');
          const meResponse = await fetch('/api/auth/me', {
            method: 'GET',
            credentials: 'include',
            headers: {
              'Cache-Control': 'no-cache, no-store, must-revalidate',
              'Pragma': 'no-cache',
              'Expires': '0'
            }
          });
          
          console.log('Auth/me response status:', meResponse.status);
          
          if (meResponse.ok) {
            const meData = await meResponse.json();
            console.log('Auth/me response data:', meData);
            
            if (meData?.success && meData.user) {
              console.log('Authentication verified, setting user in context');
              setUser(meData.user);
              return { success: true };
            } else {
              console.error('Auth/me response missing user data:', meData);
            }
          } else {
            console.error('Auth/me request failed with status:', meResponse.status);
            const errorText = await meResponse.text().catch(() => 'No error details');
            console.error('Auth/me error response:', errorText);
          }
          
          // If we get here, auth verification failed
          console.error('Auth verification failed after login');
          return { 
            success: false, 
            message: 'Đăng nhập thành công nhưng không thể xác minh trạng thái. Vui lòng làm mới trang.' 
          };
          
        } catch (verifyError) {
          console.error('Error during auth verification:', verifyError);
          return { 
            success: false, 
            message: 'Đăng nhập thành công nhưng có lỗi khi xác minh. Vui lòng thử lại.' 
          };
        }
      } else {
        console.error('Login failed with status:', res.status, 'Response:', data);
        return { 
          success: false, 
          message: data?.message || `Đăng nhập thất bại (Mã lỗi: ${res.status})` 
        };
      }
    } catch (error) {
      console.error('Unexpected error during login:', error);
      return { 
        success: false, 
        message: error instanceof Error ? error.message : 'Lỗi không xác định' 
      };
    } finally {
      console.log('=== Login Attempt Completed ===');
    }
  };

  const logout = async () => {
    try {
      // Clear cache immediately
      cachedUser = null;
      setUser(null);
      
      // Clear token from cookies
      document.cookie = 'token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
      
      // Call logout API
      await fetch('/api/auth/logout', { 
        method: 'POST',
        credentials: 'include',
        headers: {
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache'
        }
      });
      
      // Force refresh to ensure all state is cleared
      window.location.href = '/';
    } catch (error) {
      console.error('Logout error:', error);
      // Even if logout API fails, clear local state
      window.location.href = '/';
    }
  };

  // Check for out-of-sync state in a useEffect
  useEffect(() => {
    const hasUser = user !== null;
    const hasToken = document.cookie.includes('token=');
    
    // If we think we're authenticated but don't have a token, sync state
    if (hasUser && !hasToken) {
      console.warn('User state out of sync - clearing auth state');
      setUser(null);
    }
  }, [user]);

  const isAuthenticated = useCallback(() => {
    // Check both user state and token in cookie
    const hasUser = user !== null;
    const hasToken = document.cookie.includes('token=');
    
    return hasUser && hasToken;
  }, [user]);

  const isAdmin = () => {
    return user?.role === 'admin';
  };

  const refreshUser = useCallback(async () => {
    // Force refresh by bypassing cache
    await checkAuth(true);
  }, [checkAuth]);

  return {
    user,
    isLoading,
    login,
    logout,
    isAuthenticated,
    isAdmin,
    refreshUser,
  };
}

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const auth = useAuthStandalone();
  return (
    <AuthContext.Provider value={auth}>
      {children}
    </AuthContext.Provider>
  );
}
