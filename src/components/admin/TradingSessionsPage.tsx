'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/useAuth';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Loader2, TrendingUp, TrendingDown, Clock } from 'lucide-react';
import { useToast } from '@/components/ui/use-toast';
import { format } from 'date-fns';
import { vi } from 'date-fns/locale';

interface User {
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
}

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<{ success: boolean; message?: string }>;
  logout: () => Promise<void>;
  isAuthenticated: () => boolean;
  isAdmin: () => boolean;
  refreshUser: () => Promise<void>;
}

interface TradingSession {
  _id: string;
  sessionId: string;
  result: 'UP' | 'DOWN';
  startTime: string;
  endTime: string;
  status: 'active' | 'completed';
  createdAt: string;
  updatedAt: string;
}

export default function TradingSessionsPage() {
  const router = useRouter();
  const { user, isLoading: authLoading, isAdmin } = useAuth();
  const { toast } = useToast();
  const [sessions, setSessions] = useState<TradingSession[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!authLoading && !user) {
      router.push('/login');
      return;
    }

    if (user && !isAdmin()) {
      router.push('/');
      return;
    }

    fetchSessions();
  }, [user, authLoading, router]);

  const fetchSessions = async () => {
    try {
      setIsLoading(true);
      setError(null);
      
      const response = await fetch('/api/admin/sessions', {
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || 'Failed to fetch sessions');
      }

      const data = await response.json();
      setSessions(data);
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'An unknown error occurred';
      console.error('Error fetching sessions:', error);
      setError(errorMessage);
      toast({
        title: 'Error',
        description: errorMessage,
        variant: 'destructive',
      });
    } finally {
      setIsLoading(false);
    }
  };

  const formatDateTime = (dateString: string) => {
    return format(new Date(dateString), 'HH:mm:ss dd/MM/yyyy', { locale: vi });
  };

  if (authLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="bg-red-50 border border-red-200 rounded-md p-4">
          <div className="flex">
            <div className="flex-shrink-0">
              <svg
                className="h-5 w-5 text-red-400"
                viewBox="0 0 20 20"
                fill="currentColor"
              >
                <path
                  fillRule="evenodd"
                  d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                  clipRule="evenodd"
                />
              </svg>
            </div>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-red-800">{error}</h3>
              <div className="mt-2 text-sm text-red-700">
                <p>Please try again later or contact support if the problem persists.</p>
              </div>
              <div className="mt-4">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={fetchSessions}
                  className="text-red-700 hover:bg-red-100"
                >
                  Retry
                </Button>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Quản lý phiên giao dịch</h1>
        <Button onClick={() => router.push('/admin/sessions/new')}>
          Tạo phiên mới
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Danh sách phiên giao dịch</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center p-8">
              <Loader2 className="h-8 w-8 animate-spin" />
            </div>
          ) : sessions.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              Chưa có phiên giao dịch nào
            </div>
          ) : (
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>ID phiên</TableHead>
                    <TableHead>Kết quả</TableHead>
                    <TableHead>Thời gian bắt đầu</TableHead>
                    <TableHead>Thời gian kết thúc</TableHead>
                    <TableHead>Trạng thái</TableHead>
                    <TableHead className="text-right">Hành động</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sessions.map((session) => (
                    <TableRow key={session._id}>
                      <TableCell className="font-medium">
                        {session.sessionId}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center">
                          {session.result === 'UP' ? (
                            <TrendingUp className="h-4 w-4 text-green-500 mr-1" />
                          ) : (
                            <TrendingDown className="h-4 w-4 text-red-500 mr-1" />
                          )}
                          <span
                            className={
                              session.result === 'UP'
                                ? 'text-green-600 font-medium'
                                : 'text-red-600 font-medium'
                            }
                          >
                            {session.result === 'UP' ? 'TĂNG' : 'GIẢM'}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center">
                          <Clock className="h-4 w-4 text-gray-500 mr-1" />
                          {formatDateTime(session.startTime)}
                        </div>
                      </TableCell>
                      <TableCell>
                        {session.status === 'completed' ? (
                          <div className="flex items-center">
                            <Clock className="h-4 w-4 text-gray-500 mr-1" />
                            {formatDateTime(session.endTime)}
                          </div>
                        ) : (
                          <span className="text-gray-400">Đang diễn ra...</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            session.status === 'active' ? 'default' : 'secondary'
                          }
                          className={
                            session.status === 'active'
                              ? 'bg-green-100 text-green-800'
                              : 'bg-gray-100 text-gray-800'
                          }
                        >
                          {session.status === 'active' ? 'ĐANG HOẠT ĐỘNG' : 'ĐÃ KẾT THÚC'}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() =>
                            router.push(`/admin/sessions/${session._id}`)
                          }
                        >
                          Chi tiết
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
                </CardContent>
      </Card>

      {/* Session Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Tổng số phiên</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {sessions.length}
            </div>
            <p className="text-xs text-gray-500 mt-1">
              Tổng số phiên giao dịch đã tạo
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Phiên tăng</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">
              {sessions.filter(s => s.result === 'UP').length}
            </div>
            <p className="text-xs text-gray-500 mt-1">
              Tổng số phiên kết quả tăng
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Phiên giảm</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">
              {sessions.filter(s => s.result === 'DOWN').length}
            </div>
            <p className="text-xs text-gray-500 mt-1">
              Tổng số phiên kết quả giảm
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Recent Activity */}
      <Card>
        <CardHeader>
          <CardTitle>Hoạt động gần đây</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {sessions.slice(0, 5).map((session) => (
              <div key={session._id} className="flex items-center justify-between p-4 border rounded-lg">
                <div className="flex items-center space-x-4">
                  <div className={`p-2 rounded-full ${
                    session.result === 'UP' ? 'bg-green-100 text-green-600' : 'bg-red-100 text-red-600'
                  }`}>
                    {session.result === 'UP' ? (
                      <TrendingUp className="h-5 w-5" />
                    ) : (
                      <TrendingDown className="h-5 w-5" />
                    )}
                  </div>
                  <div>
                    <p className="font-medium">
                      Phiên {session.sessionId} - {session.result === 'UP' ? 'TĂNG' : 'GIẢM'}
                    </p>
                    <p className="text-sm text-gray-500">
                      {formatDateTime(session.startTime)}
                    </p>
                  </div>
                </div>
                <Badge
                  variant={session.status === 'active' ? 'default' : 'outline'}
                  className={session.status === 'active' ? 'bg-blue-100 text-blue-800' : ''}
                >
                  {session.status === 'active' ? 'ĐANG HOẠT ĐỘNG' : 'ĐÃ KẾT THÚC'}
                </Badge>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}