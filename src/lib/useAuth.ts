import React, { useState, useEffect, useCallback } from 'react';

export interface User {
  id: string;
  username: string;
  avatar?: string;
  role?: string;
  balance?: number;
}

export type AuthContextType = {
  user: User | null;
  token: string | null;
  loading: boolean;
  isAuthenticated: () => boolean;
  isAdmin: () => boolean;
  login: (username: string, password: string) => Promise<{ success: boolean; message?: string }>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
};

export function useAuth(): AuthContextType {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Load user and token from localStorage on mount
    const storedUser = localStorage.getItem('user');
    const storedToken = localStorage.getItem('token');
    if (storedUser && storedToken) {
      setUser(JSON.parse(storedUser));
      setToken(storedToken);
    }
    setLoading(false);
  }, []);

  const isAuthenticated = useCallback(() => {
    return !!user && !!token;
  }, [user, token]);

  const isAdmin = useCallback(() => {
    return isAuthenticated() && user?.role === 'admin';
  }, [user, isAuthenticated]);

  const login = async (username: string, password: string) => {
    try {
      // This is a placeholder - replace with actual API call
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });
      
      const data = await response.json();
      
      if (response.ok && data.success) {
        setUser(data.user);
        setToken(data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        localStorage.setItem('token', data.token);
        return { success: true };
      } else {
        return { success: false, message: data.message || 'Login failed' };
      }
    } catch (error) {
      console.error('Login error:', error);
      return { success: false, message: 'An error occurred during login' };
    }
  };

  const logout = async () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('user');
    localStorage.removeItem('token');
  };

  const refreshUser = async () => {
    // Placeholder for refreshing user data
    if (token) {
      try {
        const response = await fetch('/api/auth/verify', {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });
        const data = await response.json();
        if (response.ok && data.valid) {
          setUser(data.user);
          localStorage.setItem('user', JSON.stringify(data.user));
        } else {
          await logout();
        }
      } catch (error) {
        console.error('Error refreshing user:', error);
        await logout();
      }
    }
  };

  return {
    user,
    token,
    loading,
    isAuthenticated,
    isAdmin,
    login,
    logout,
    refreshUser,
  };
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // This is a placeholder since we're using useAuth hook directly
  return <>{children}</>;
};
