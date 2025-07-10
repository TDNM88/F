'use client';

import { useState } from 'react';
import { useAuth } from '@/lib/useAuth';
import { fetcher } from '@/lib/fetcher';
import useSWR from 'swr';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Withdrawal } from '@/types';

export default function WithdrawHistoryPage() {
  const { user } = useAuth();
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 10;

  // Fetch withdrawal history
  const { data, error, isLoading } = useSWR<{ withdrawals: Withdrawal[], total: number }>(
    `/api/withdrawals/history?page=${currentPage}&limit=${pageSize}`,
    fetcher
  );

  // Get status badge variant based on withdrawal status
  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'pending':
        return { variant: 'warning' as const, label: 'Đang xử lý' };
      case 'approved':
        return { variant: 'success' as const, label: 'Đã duyệt' };
      case 'rejected':
        return { variant: 'destructive' as const, label: 'Từ chối' };
      default:
        return { variant: 'secondary' as const, label: status };
    }
  };

  // Format date
  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('vi-VN', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  // Calculate total pages
  const totalPages = data ? Math.ceil(data.total / pageSize) : 0;

  // Handle pagination
  const handlePageChange = (page: number) => {
    setCurrentPage(page);
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Lịch sử rút tiền</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="text-center py-8">
              <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary mx-auto mb-4"></div>
              <p>Đang tải dữ liệu...</p>
            </div>
          ) : error ? (
            <div className="text-center py-8 text-red-500">
              Đã xảy ra lỗi khi tải dữ liệu. Vui lòng thử lại sau.
            </div>
          ) : !data || data.withdrawals.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              Không có lịch sử rút tiền nào.
            </div>
          ) : (
            <div>
              <div className="overflow-x-auto">
                <table className="w-full border-collapse">
                  <thead>
                    <tr className="bg-gray-50 border-b">
                      <th className="py-3 px-4 text-left">ID</th>
                      <th className="py-3 px-4 text-left">Ngày</th>
                      <th className="py-3 px-4 text-right">Số tiền</th>
                      <th className="py-3 px-4 text-left">Ngân hàng</th>
                      <th className="py-3 px-4 text-left">Trạng thái</th>
                      <th className="py-3 px-4 text-left">Ghi chú</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.withdrawals.map((withdrawal) => {
                      const statusBadge = getStatusBadge(withdrawal.status);
                      return (
                        <tr key={withdrawal._id} className="border-b hover:bg-gray-50">
                          <td className="py-3 px-4 text-gray-500">
                            {withdrawal._id.substring(withdrawal._id.length - 6)}
                          </td>
                          <td className="py-3 px-4">
                            {formatDate(withdrawal.createdAt)}
                          </td>
                          <td className="py-3 px-4 text-right font-medium">
                            {withdrawal.amount.toLocaleString('vi-VN')} VND
                          </td>
                          <td className="py-3 px-4">
                            {withdrawal.bank?.bankName || 'N/A'}
                          </td>
                          <td className="py-3 px-4">
                            <Badge variant={statusBadge.variant}>
                              {statusBadge.label}
                            </Badge>
                          </td>
                          <td className="py-3 px-4 text-sm max-w-[200px] truncate">
                            {withdrawal.notes || '—'}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="flex justify-center items-center space-x-2 mt-6">
                  <button
                    onClick={() => handlePageChange(currentPage - 1)}
                    disabled={currentPage === 1}
                    className={`px-3 py-1 rounded ${currentPage === 1 ? 'text-gray-400 cursor-not-allowed' : 'text-blue-600 hover:bg-blue-50'}`}
                  >
                    Trước
                  </button>
                  
                  {Array.from({ length: totalPages }, (_, i) => i + 1).map((page) => (
                    <button
                      key={page}
                      onClick={() => handlePageChange(page)}
                      className={`px-3 py-1 rounded ${currentPage === page ? 'bg-blue-600 text-white' : 'hover:bg-blue-50'}`}
                    >
                      {page}
                    </button>
                  ))}
                  
                  <button
                    onClick={() => handlePageChange(currentPage + 1)}
                    disabled={currentPage === totalPages}
                    className={`px-3 py-1 rounded ${currentPage === totalPages ? 'text-gray-400 cursor-not-allowed' : 'text-blue-600 hover:bg-blue-50'}`}
                  >
                    Sau
                  </button>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
