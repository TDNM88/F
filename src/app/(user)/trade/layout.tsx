'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/useAuth';
import { Button } from '@/components/ui/button';
import { User, LogOut } from 'lucide-react';

export default function TradeLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const { isAuthenticated, isLoading, user, logout } = useAuth();

  // Function to handle logout
  const handleLogout = () => {
    logout();
    router.push('/login');
  };

  // Show loading state while checking authentication
  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-900">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  // Only render the layout if authenticated
  if (!isAuthenticated()) {
    return null;
  }

  return (
    <div className="min-h-screen bg-white">
      <div className="p-4 md:p-8">
        {children}
      </div>
    </div>
  );
}