'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/useAuth';
import AdminSidebar from '@/components/admin-sidebar';

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const { isAuthenticated, isLoading, isAdmin } = useAuth();

  // Redirect to login if not authenticated or not admin
  useEffect(() => {
    if (!isLoading) {
      if (!isAuthenticated()) {
        router.push('/login');
      } else if (!isAdmin()) {
        router.push('/trade'); // Redirect to user area if not admin
      }
    }
  }, [isLoading, isAuthenticated, isAdmin, router]);

  // Show loading state while checking authentication
  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary"></div>
      </div>
    );
  }

  // Only render the layout if authenticated and is admin
  if (!isAuthenticated() || !isAdmin()) {
    return null;
  }

  return (
    <div className="bg-gray-50 min-h-screen">
      <div className="container mx-auto py-6 px-4">
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
          <div className="lg:col-span-1">
            <AdminSidebar />
          </div>
          <div className="lg:col-span-4">
            {children}
          </div>
        </div>
      </div>
    </div>
  );
}
