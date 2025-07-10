'use client';

import { useState, useEffect } from 'react';
import { useAuth } from '@/lib/useAuth';
import { fetcher } from '@/lib/fetcher';
import useSWR from 'swr';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../../../components/ui/tabs';

export default function OrdersPage() {
  const { user, token, loading } = useAuth();
  const [currentPage, setCurrentPage] = useState(1);
  const [activeTab, setActiveTab] = useState('deposits');
  const pageSize = 10;

  // Fetch deposit history
  const { 
    data: depositData, 
    error: depositError, 
    isLoading: depositLoading 
  } = useSWR(
    activeTab === 'deposits' ? `/api/deposits/history?page=${currentPage}&limit=${pageSize}` : null,
    fetcher
  );

  // Fetch withdrawal history
  const { 
    data: withdrawalData, 
    error: withdrawalError, 
    isLoading: withdrawalLoading 
  } = useSWR(
    activeTab === 'withdrawals' ? `/api/withdrawals/history?page=${currentPage}&limit=${pageSize}` : null,
    fetcher
  );

  // Reset pagination when changing tabs
  useEffect(() => {
    setCurrentPage(1);
  }, [activeTab]);

  // Get status badge variant based on status
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
  const totalPages = activeTab === 'deposits'
    ? (depositData ? Math.ceil(depositData.total / pageSize) : 0)
    : (withdrawalData ? Math.ceil(withdrawalData.total / pageSize) : 0);

  // Handle pagination
  const handlePageChange = (page: number) => {
    setCurrentPage(page);
  };

  const isLoading = activeTab === 'deposits' ? depositLoading : withdrawalLoading;
  const error = activeTab === 'deposits' ? depositError : withdrawalError;
  const data = activeTab === 'deposits' ? depositData : withdrawalData;

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-6">Lịch sử giao dịch</h1>
        
        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full max-w-md grid-cols-2 bg-gray-100 p-1 rounded-md">
            <TabsTrigger 
              value="deposits" 
              className="text-sm font-medium text-gray-700 data-[state=active]:bg-white data-[state=active]:text-blue-600 data-[state=active]:shadow-sm rounded-md transition-all duration-200"
            >
              Lịch sử nạp tiền
            </TabsTrigger>
            <TabsTrigger 
              value="withdrawals" 
              className="text-sm font-medium text-gray-700 data-[state=active]:bg-white data-[state=active]:text-blue-600 data-[state=active]:shadow-sm rounded-md transition-all duration-200"
            >
              Lịch sử rút tiền
            </TabsTrigger>
          </TabsList>
          
          <TabsContent value="deposits" className="mt-6">
            <Card className="border border-gray-200 shadow-sm rounded-lg">
              <CardHeader className="border-b border-gray-200 p-6">
                <CardTitle className="text-xl font-semibold text-gray-900">Lịch sử nạp tiền</CardTitle>
              </CardHeader>
              <CardContent className="p-6">
                {isLoading ? (
                  <div className="text-center py-10">
                    <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-600 mx-auto mb-4"></div>
                    <p className="text-gray-600">Đang tải dữ liệu...</p>
                  </div>
                ) : error ? (
                  <div className="text-center py-10 text-red-600">
                    Đã xảy ra lỗi khi tải dữ liệu. Vui lòng thử lại sau.
                  </div>
                ) : !data || !data.deposits || data.deposits.length === 0 ? (
                  <div className="text-center py-10 text-gray-500">
                    Không có lịch sử nạp tiền nào.
                  </div>
                ) : (
                  <div>
                    <div className="overflow-x-auto">
                      <table className="w-full border-collapse">
                        <thead>
                          <tr className="bg-gray-50 border-b border-gray-200">
                            <th className="py-3 px-4 text-left text-sm font-medium text-gray-600">ID</th>
                            <th className="py-3 px-4 text-left text-sm font-medium text-gray-600">Ngày</th>
                            <th className="py-3 px-4 text-right text-sm font-medium text-gray-600">Số tiền</th>
                            <th className="py-3 px-4 text-left text-sm font-medium text-gray-600">Trạng thái</th>
                            <th className="py-3 px-4 text-left text-sm font-medium text-gray-600">Ghi chú</th>
                          </tr>
                        </thead>
                        <tbody>
                          {data.deposits.map((deposit: any) => {
                            const statusBadge = getStatusBadge(deposit.status);
                            return (
                              <tr key={deposit._id} className="border-b border-gray-200 hover:bg-gray-100 transition-colors">
                                <td className="py-4 px-4 text-sm text-gray-500">
                                  {deposit._id.substring(deposit._id.length - 6)}
                                </td>
                                <td className="py-4 px-4 text-sm text-gray-700">
                                  {formatDate(deposit.createdAt)}
                                </td>
                                <td className="py-4 px-4 text-sm font-medium text-gray-900 text-right">
                                  {deposit.amount.toLocaleString('vi-VN')} VND
                                </td>
                                <td className="py-4 px-4 text-sm">
                                  <Badge variant={statusBadge.variant} className="text-xs">
                                    {statusBadge.label}
                                  </Badge>
                                </td>
                                <td className="py-4 px-4 text-sm text-gray-600 max-w-[200px] truncate">
                                  {deposit.notes || '—'}
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
                          className={`px-3 py-1 text-sm rounded-md ${currentPage === 1 ? 'text-gray-400 cursor-not-allowed' : 'text-blue-600 hover:bg-blue-50'}`}
                        >
                          Trước
                        </button>
                        {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                          let pageNum = i + 1;
                          if (totalPages > 5 && currentPage > 3) {
                            pageNum = currentPage - 3 + i;
                          }
                          if (pageNum > totalPages) return null;
                          return (
                            <button
                              key={pageNum}
                              onClick={() => handlePageChange(pageNum)}
                              className={`px-3 py-1 text-sm rounded-md ${currentPage === pageNum ? 'bg-blue-600 text-white' : 'text-gray-700 hover:bg-gray-100'}`}
                            >
                              {pageNum}
                            </button>
                          );
                        })}
                        <button
                          onClick={() => handlePageChange(currentPage + 1)}
                          disabled={currentPage === totalPages}
                          className={`px-3 py-1 text-sm rounded-md ${currentPage === totalPages ? 'text-gray-400 cursor-not-allowed' : 'text-blue-600 hover:bg-blue-50'}`}
                        >
                          Sau
                        </button>
                      </div>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="withdrawals" className="mt-6">
            <Card className="border border-gray-200 shadow-sm rounded-lg">
              <CardHeader className="border-b border-gray-200 p-6">
                <CardTitle className="text-xl font-semibold text-gray-900">Lịch sử rút tiền</CardTitle>
              </CardHeader>
              <CardContent className="p-6">
                {isLoading ? (
                  <div className="text-center py-10">
                    <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-600 mx-auto mb-4"></div>
                    <p className="text-gray-600">Đang tải dữ liệu...</p>
                  </div>
                ) : error ? (
                  <div className="text-center py-10 text-red-600">
                    Đã xảy ra lỗi khi tải dữ liệu. Vui lòng thử lại sau.
                  </div>
                ) : !data || !data.withdrawals || data.withdrawals.length === 0 ? (
                  <div className="text-center py-10 text-gray-500">
                    Không có lịch sử rút tiền nào.
                  </div>
                ) : (
                  <div>
                    <div className="overflow-x-auto">
                      <table className="w-full border-collapse">
                        <thead>
                          <tr className="bg-gray-50 border-b border-gray-200">
                            <th className="py-3 px-4 text-left text-sm font-medium text-gray-600">ID</th>
                            <th className="py-3 px-4 text-left text-sm font-medium text-gray-600">Ngày</th>
                            <th className="py-3 px-4 text-right text-sm font-medium text-gray-600">Số tiền</th>
                            <th className="py-3 px-4 text-left text-sm font-medium text-gray-600">Ngân hàng</th>
                            <th className="py-3 px-4 text-left text-sm font-medium text-gray-600">Số tài khoản</th>
                            <th className="py-3 px-4 text-left text-sm font-medium text-gray-600">Trạng thái</th>
                          </tr>
                        </thead>
                        <tbody>
                          {data.withdrawals.map((withdrawal: any) => {
                            const statusBadge = getStatusBadge(withdrawal.status);
                            return (
                              <tr key={withdrawal._id} className="border-b border-gray-200 hover:bg-gray-100 transition-colors">
                                <td className="py-4 px-4 text-sm text-gray-500">
                                  {withdrawal._id.substring(withdrawal._id.length - 6)}
                                </td>
                                <td className="py-4 px-4 text-sm text-gray-700">
                                  {formatDate(withdrawal.createdAt)}
                                </td>
                                <td className="py-4 px-4 text-sm font-medium text-gray-900 text-right">
                                  {withdrawal.amount.toLocaleString('vi-VN')} VND
                                </td>
                                <td className="py-4 px-4 text-sm text-gray-700">
                                  {withdrawal.bankName || 'N/A'}
                                </td>
                                <td className="py-4 px-4 text-sm text-gray-700">
                                  {withdrawal.accountNumber || 'N/A'}
                                </td>
                                <td className="py-4 px-4 text-sm">
                                  <Badge variant={statusBadge.variant} className="text-xs">
                                    {statusBadge.label}
                                  </Badge>
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
                          className={`px-3 py-1 text-sm rounded-md ${currentPage === 1 ? 'text-gray-400 cursor-not-allowed' : 'text-blue-600 hover:bg-blue-50'}`}
                        >
                          Trước
                        </button>
                        {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                          let pageNum = i + 1;
                          if (totalPages > 5 && currentPage > 3) {
                            pageNum = currentPage - 3 + i;
                          }
                          if (pageNum > totalPages) return null;
                          return (
                            <button
                              key={pageNum}
                              onClick={() => handlePageChange(pageNum)}
                              className={`px-3 py-1 text-sm rounded-md ${currentPage === pageNum ? 'bg-blue-600 text-white' : 'text-gray-700 hover:bg-gray-100'}`}
                            >
                              {pageNum}
                            </button>
                          );
                        })}
                        <button
                          onClick={() => handlePageChange(currentPage + 1)}
                          disabled={currentPage === totalPages}
                          className={`px-3 py-1 text-sm rounded-md ${currentPage === totalPages ? 'text-gray-400 cursor-not-allowed' : 'text-blue-600 hover:bg-blue-50'}`}
                        >
                          Sau
                        </button>
                      </div>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}