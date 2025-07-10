"use client"

import { useEffect } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { useAuth } from '@/lib/useAuthNew';
import { Loader2 } from 'lucide-react';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredRole?: 'admin' | 'user';
  redirectTo?: string;
}

export function ProtectedRoute({ 
  children, 
  requiredRole = 'user', 
  redirectTo 
}: ProtectedRouteProps) {
  const { user, isLoading, isAuthenticated, isAdmin } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    // Only run this effect after the initial auth check is complete
    if (!isLoading) {
      // If not authenticated, redirect to login
      if (!isAuthenticated()) {
        const callbackUrl = redirectTo || pathname;
        const loginUrl = `/login${callbackUrl ? `?callbackUrl=${encodeURIComponent(callbackUrl)}` : ''}`;
        router.push(loginUrl);
        return;
      }

      // Check role-based access
      if (requiredRole === 'admin' && !isAdmin()) {
        // Non-admin trying to access admin route
        router.push('/');
        return;
      }

      // Optional: Redirect admins away from user routes if needed
      if (requiredRole === 'user' && isAdmin() && pathname.startsWith('/user')) {
        router.push('/admin');
        return;
      }
    }
  }, [isLoading, isAuthenticated, isAdmin, requiredRole, router, pathname, redirectTo]);

  // Show loading indicator while checking auth
  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-white">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="h-12 w-12 animate-spin text-blue-500" />
          <p className="text-gray-600">Đang kiểm tra quyền truy cập...</p>
        </div>
      </div>
    );
  }

  // If not authenticated or role doesn't match, don't render anything
  // The useEffect will handle the redirect
  if (!isAuthenticated() || (requiredRole === 'admin' && !isAdmin())) {
    return null;
  }

  // If we get here, user is authenticated and has the correct role
  return <>{children}</>;
}
