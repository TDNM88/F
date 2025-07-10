"use client";

import React, { useState, useEffect, useRef, useCallback, ChangeEvent, FormEvent } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useAuth } from '@/lib/useAuth';
import { Button } from '@/components/ui/button';
import { useToast } from '@/components/ui/use-toast';
import Link from 'next/link';
import { Menu, X, Loader2, Upload, CheckCircle, XCircle, UploadCloud } from 'lucide-react';
import { A } from 'framer-motion/dist/types.d-D0HXPxHm';

type TabType = 'overview' | 'bank' | 'verify' | 'password';

interface BankForm {
  fullName: string;
  bankType: string;
  bankName: string;
  accountNumber: string;
}

interface PasswordForm {
  currentPassword: string;
  newPassword: string;
  confirmPassword: string;
}

interface UploadStatus {
  success: boolean;
  message: string;
}

interface UploadState {
  front: UploadStatus | null;
  back: UploadStatus | null;
}

interface BankInfo {
  accountHolder: string;
  name: string;
  bankName: string;
  accountNumber: string;
  accountType?: string;
  bankType?: string;
  bankCode?: string;
  verified?: boolean;
}

interface VerificationData {
  verified: boolean;
  cccdFront: string;
  cccdBack: string;
  submittedAt?: string;
  status?: 'pending' | 'approved' | 'rejected';
  reviewedAt?: string;
  reviewedBy?: string;
  rejectionReason?: string;
}

interface BalanceInfo {
  available: number;
  locked?: number;
  total?: number;
}

interface User {
  _id?: string;
  id?: string;
  username?: string;
  email?: string;
  phone?: string;
  fullName?: string;
  address?: string;
  dateOfBirth?: string;
  gender?: string;
  bankInfo?: BankInfo;
  bank?: BankInfo;
  verification?: VerificationData;
  balance?: BalanceInfo | number;
  createdAt?: string;
  updatedAt?: string;
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

export default function AccountPage() {
  const { user, isLoading, logout, refreshUser } = useAuth() as AuthContextType;
  const router = useRouter();
  const searchParams = useSearchParams();
  const { toast } = useToast();
  const toastVariant = {
    default: 'default' as const,
    destructive: 'destructive' as const,
    success: 'success' as const,
    error: 'destructive' as const,
  } as const;

  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [isClient, setIsClient] = useState(false);
  const [verificationStatus, setVerificationStatus] = useState({
    verified: false,
    cccdFront: '',
    cccdBack: '',
    submittedAt: '',
  });

  const [frontIdFile, setFrontIdFile] = useState<File | null>(null);
  const [backIdFile, setBackIdFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState<UploadState>({
    front: null,
    back: null
  });

  const [bankForm, setBankForm] = useState<BankInfo>({
    accountHolder: user?.bankInfo?.accountHolder || user?.bank?.accountHolder || '',
    name: user?.bankInfo?.name || user?.bank?.name || '',
    bankName: user?.bankInfo?.bankName || user?.bank?.bankName || '',
    accountNumber: user?.bankInfo?.accountNumber || user?.bank?.accountNumber || '',
    accountType: user?.bankInfo?.accountType || 'savings',
    bankType: user?.bankInfo?.bankType || '',
    bankCode: user?.bankInfo?.bankCode || '',
    verified: user?.bankInfo?.verified || false
  });

  const [passwordForm, setPasswordForm] = useState<PasswordForm>({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });

  const [isEditingBankInfo, setIsEditingBankInfo] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [passwordError, setPasswordError] = useState('');

  useEffect(() => {
    if (user?.verification) {
      setVerificationStatus({
        verified: user.verification.verified || false,
        cccdFront: user.verification.cccdFront || '',
        cccdBack: user.verification.cccdBack || '',
        submittedAt: user.verification.submittedAt || ''
      });
    }
  }, [user]);

  const isVerified = verificationStatus.verified;

  useEffect(() => {
    const checkAuth = async () => {
      // Only check auth if we don't have user data yet
      if (!user) {
        try {
          await refreshUser();
        } catch (error) {
          console.error('Failed to refresh user data:', error);
        }
      }
    };

    checkAuth();
  }, [user, refreshUser]);

  useEffect(() => {
    setIsClient(true);
  }, []);

  const getBalance = (balance: number | BalanceInfo | undefined): number => {
    if (balance === undefined) return 0;
    if (typeof balance === 'number') return balance;
    if (balance && 'available' in balance) return Number(balance.available) || 0;
    return 0;
  };

  const formatCurrency = (amount: number): string => {
    return new Intl.NumberFormat('vi-VN', {
      style: 'currency',
      currency: 'VND',
      minimumFractionDigits: 0,
      maximumFractionDigits: 0
    }).format(amount);
  };

  const getToken = (): string | null => {
    if (typeof window === 'undefined') return null;
    
    // Try to get token from localStorage first
    const token = localStorage.getItem('authToken');
    if (token) return token;
    
    // If still not found, try to get it from cookies
    const cookies = document.cookie.split(';').reduce((cookies, cookie) => {
      const [name, value] = cookie.split('=').map(c => c.trim());
      cookies[name] = value;
      return cookies;
    }, {} as Record<string, string>);
    
    return cookies.authToken || null;
  };

  const formatDate = (dateString?: string): string => {
    if (!dateString) return '';
    const date = new Date(dateString);
    return `${date.getDate().toString().padStart(2, '0')}/${(date.getMonth() + 1).toString().padStart(2, '0')}/${date.getFullYear()} ${date.getHours().toString().padStart(2, '0')}:${date.getMinutes().toString().padStart(2, '0')}`;
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>, type: 'front' | 'back') => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!['image/jpeg', 'image/png'].includes(file.type)) {
      toast({
        title: 'Lỗi',
        description: 'Chỉ chấp nhận file ảnh định dạng JPG hoặc PNG',
        variant: 'destructive',
      });
      return;
    }

    if (file.size > 5 * 1024 * 1024) {
      toast({
        title: 'Lỗi',
        description: 'Kích thước file tối đa là 5MB',
        variant: 'destructive',
      });
      return;
    }

    if (type === 'front') {
      setFrontIdFile(file);
      setUploadStatus(prev => ({ ...prev, front: null }));
    } else {
      setBackIdFile(file);
      setUploadStatus(prev => ({ ...prev, back: null }));
    }
  };

  const handleUpload = async (type: 'front' | 'back') => {
    const file = type === 'front' ? frontIdFile : backIdFile;
    if (!file) {
      toast({
        title: 'Lỗi',
        description: 'Vui lòng chọn tệp để tải lên',
        variant: 'destructive',
      });
      return;
    }

    // Check authentication first
    const token = getToken();
    if (!token) {
      toast({
        title: 'Lỗi xác thực',
        description: 'Vui lòng đăng nhập lại để tiếp tục',
        variant: 'destructive',
      });
      router.push('/login');
      return;
    }

    setIsUploading(true);
    setUploadStatus(prev => ({ ...prev, [type]: { status: 'uploading' } }));

    const formData = new FormData();
    formData.append('file', file);
    formData.append('type', type);

    try {
      // Get fresh token on each request
      const token = getToken();
      if (!token) {
        throw new Error('Không tìm thấy thông tin xác thực. Vui lòng đăng nhập lại.');
      }

      // Add cache-control headers to prevent caching
      const headers = new Headers();
      headers.append('Authorization', `Bearer ${token}`);
      headers.append('Cache-Control', 'no-cache, no-store, must-revalidate');
      headers.append('Pragma', 'no-cache');
      headers.append('Expires', '0');

      const response = await fetch('/api/upload-verification', {
        method: 'POST',
        headers: headers,
        body: formData,
        credentials: 'include', // Include cookies in the request
        cache: 'no-store' // Prevent caching
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.message || 'Có lỗi xảy ra khi tải lên ảnh');
      }

      const data = await response.json();
      setVerificationStatus(prev => ({
        ...prev,
        [type === 'front' ? 'cccdFront' : 'cccdBack']: data.url,
        status: 'pending',
        submittedAt: new Date().toISOString()
      }));

      // Refresh user data after successful upload
      await refreshUser();
      
      toast({
        title: 'Thành công',
        description: `Đã tải lên ảnh ${type === 'front' ? 'mặt trước' : 'mặt sau'} thành công`,
        variant: 'success',
      });
      
      // Reset the file input
      if (type === 'front') {
        setFrontIdFile(null);
      } else {
        setBackIdFile(null);
      }

      setUploadStatus(prev => ({
        ...prev,
        [type]: { success: true, message: 'Tải lên thành công' }
      }));
    } catch (error) {
      console.error(`Lỗi khi tải lên ảnh ${type === 'front' ? 'mặt trước' : 'mặt sau'}:`, error);
      
      toast({
        title: 'Lỗi',
        description: error instanceof Error ? error.message : 'Có lỗi xảy ra khi tải lên ảnh',
        variant: 'error',
      });

      setUploadStatus(prev => ({
        ...prev,
        [type]: { success: false, message: error instanceof Error ? error.message : 'Có lỗi xảy ra' }
      }));
    } finally {
      setIsUploading(false);
    }
  };

  const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setPasswordForm(prev => ({
      ...prev,
      [name]: value
    }));

    if (passwordError) {
      setPasswordError('');
    }
  };

  const handleBankInfoChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setBankForm(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleBankFormChange = handleBankInfoChange;

  const handleSubmitBankInfo = async (e: React.FormEvent) => {
    e.preventDefault();

    try {
      const token = getToken();
      if (!token) {
        throw new Error('Không tìm thấy token xác thực');
      }

      const response = await fetch('/api/update-bank-info', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(bankForm)
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Có lỗi xảy ra khi cập nhật thông tin ngân hàng');
      }

      const data = await response.json();

      toast({
        title: 'Thành công',
        description: 'Cập nhật thông tin ngân hàng thành công',
        variant: 'success',
      });
    } catch (error) {
      console.error('Update bank info error:', error);
      toast({
        title: 'Lỗi',
        description: error instanceof Error ? error.message : 'Có lỗi xảy ra khi cập nhật thông tin ngân hàng',
        variant: 'error',
      });
    }
  };

  const handleSubmitPassword = async (e: React.FormEvent) => {
    e.preventDefault();

    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      toast({
        title: 'Lỗi',
        description: 'Mật khẩu mới và xác nhận mật khẩu không khớp',
        variant: 'destructive',
      });
      return;
    }

    try {
      const token = getToken();
      if (!token) {
        throw new Error('Không tìm thấy token xác thực');
      }

      const response = await fetch('/api/change-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          currentPassword: passwordForm.currentPassword,
          newPassword: passwordForm.newPassword
        })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Có lỗi xảy ra khi đổi mật khẩu');
      }

      setPasswordForm({
        currentPassword: '',
        newPassword: '',
        confirmPassword: ''
      });

      toast({
        title: 'Thành công',
        description: 'Đổi mật khẩu thành công',
        variant: 'success',
      });
    } catch (error) {
      console.error('Change password error:', error);
      toast({
        title: 'Lỗi',
        description: error instanceof Error ? error.message : 'Có lỗi xảy ra khi đổi mật khẩu',
        variant: 'destructive',
      });
    }
  };

  // Handle authentication state and redirects
  useEffect(() => {
    // Only run on client side
    if (typeof window === 'undefined') return;

    // Check if we're already on the login page to prevent loops
    const isLoginPage = window.location.pathname === '/login';
    const token = getToken();
    
    // If no token and not on login page, redirect to login
    if (!token && !isLoginPage) {
      // Store the current URL to return after login
      const returnUrl = window.location.pathname + window.location.search;
      router.push(`/login?returnUrl=${encodeURIComponent(returnUrl)}`);
      return;
    }

    // If we have a token but no user data yet, try to refresh
    if (token && !user && !isLoading) {
      refreshUser().catch(() => {
        // If refresh fails, clear invalid token and redirect to login
        localStorage.removeItem('authToken');
        router.push('/login');
      });
    }
  }, [user, isLoading, router, refreshUser]);

  // Show loading state only when we're still loading and have a token
  if ((isLoading && getToken()) || (!user && getToken())) {
    return (
      <div className="min-h-screen bg-gray-900 flex justify-center items-center">
        <div className="text-center">
          <Loader2 className="w-8 h-8 mx-auto mb-4 text-blue-500 animate-spin" />
          <p className="text-gray-400">Đang tải thông tin tài khoản...</p>
        </div>
      </div>
    );
  }

  // If no user and no token, we'll be redirected by the useEffect
  if (!user) {
    return null;
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white p-4 md:p-8">
      <div className="max-w-6xl mx-auto">
        <div className="flex flex-col md:flex-row gap-6">
          {/* Sidebar - Hidden on mobile, shown on desktop */}
          <div className="hidden md:block w-64 flex-shrink-0">
            <div className="bg-gray-800 rounded-lg p-4 sticky top-4">
              <div className="flex items-center space-x-3 mb-6">
                <div className="bg-blue-600 w-12 h-12 rounded-full flex items-center justify-center text-xl font-bold">
                  {user?.username?.charAt(0).toUpperCase() || 'U'}
                </div>
                <div>
                  <h2 className="font-medium">{user.username}</h2>
                  <p className="text-sm text-gray-400">{user.email}</p>
                </div>
              </div>
              
              <nav className="space-y-1">
                <button
                  onClick={() => setActiveTab('overview')}
                  className={`w-full text-left px-4 py-2 rounded-md ${activeTab === 'overview' ? 'bg-gray-700 text-white' : 'text-gray-300 hover:bg-gray-700'}`}
                >
                  Tổng quan
                </button>
                <button
                  onClick={() => setActiveTab('bank')}
                  className={`w-full text-left px-4 py-2 rounded-md ${activeTab === 'bank' ? 'bg-gray-700 text-white' : 'text-gray-300 hover:bg-gray-700'}`}
                >
                  Thông tin ngân hàng
                </button>
                <button
                  onClick={() => setActiveTab('verify')}
                  className={`w-full text-left px-4 py-2 rounded-md ${activeTab === 'verify' ? 'bg-gray-700 text-white' : 'text-gray-300 hover:bg-gray-700'}`}
                >
                  Xác minh danh tính
                </button>
                <button
                  onClick={() => setActiveTab('password')}
                  className={`w-full text-left px-4 py-2 rounded-md ${activeTab === 'password' ? 'bg-gray-700 text-white' : 'text-gray-300 hover:bg-gray-700'}`}
                >
                  Đổi mật khẩu
                </button>
                <button
                  onClick={logout}
                  className="w-full text-left px-4 py-2 rounded-md text-red-400 hover:bg-gray-700"
                >
                  Đăng xuất
                </button>
              </nav>
            </div>
          </div>

          {/* Main Content */}
          <div className="flex-1">
            {/* Mobile Navigation - Only show on mobile */}
            <div className="md:hidden mb-6">
              <div className="bg-gray-800 rounded-lg p-4">
                <div className="flex items-center space-x-3 mb-4">
                  <div className="bg-blue-600 w-10 h-10 rounded-full flex items-center justify-center text-lg font-bold">
                    {user?.username?.charAt(0).toUpperCase() || 'U'}
                  </div>
                  <div>
                    <h2 className="font-medium text-sm">{user.username}</h2>
                    <p className="text-xs text-gray-400">{user.email}</p>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    onClick={() => setActiveTab('overview')}
                    className={`px-3 py-2 text-sm rounded ${activeTab === 'overview' ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-300'}`}
                  >
                    Tổng quan
                  </button>
                  <button
                    onClick={() => setActiveTab('bank')}
                    className={`px-3 py-2 text-sm rounded ${activeTab === 'bank' ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-300'}`}
                  >
                    Ngân hàng
                  </button>
                  <button
                    onClick={() => setActiveTab('verify')}
                    className={`px-3 py-2 text-sm rounded ${activeTab === 'verify' ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-300'}`}
                  >
                    Xác minh
                  </button>
                  <button
                    onClick={() => setActiveTab('password')}
                    className={`px-3 py-2 text-sm rounded ${activeTab === 'password' ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-300'}`}
                  >
                    Mật khẩu
                  </button>
                </div>
              </div>
            </div>
            {activeTab === 'overview' && (
              <div className="space-y-6">
                <h1 className="text-2xl font-bold">Tổng quan tài khoản</h1>
                
                <div className="bg-gray-800/50 p-6 rounded-lg">
                  <h3 className="text-lg font-medium mb-4">Thông tin cá nhân</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <p className="text-gray-400">Họ và tên</p>
                      <p>{user.fullName || 'Chưa cập nhật'}</p>
                    </div>
                    <div>
                      <p className="text-gray-400">Email</p>
                      <p>{user.email || 'Chưa cập nhật'}</p>
                    </div>
                    <div>
                      <p className="text-gray-400">Số điện thoại</p>
                      <p>{user.phone || 'Chưa cập nhật'}</p>
                    </div>
                    <div>
                      <p className="text-gray-400">Địa chỉ</p>
                      <p>{user.address || 'Chưa cập nhật'}</p>
                    </div>
                  </div>
                </div>

                <div className="bg-gray-800/50 p-6 rounded-lg">
                  <h3 className="text-lg font-medium mb-4">Trạng thái tài khoản</h3>
                  <div className="space-y-3">
                    <p>
                      <span className="text-gray-400">Xác minh danh tính:</span>{' '}
                      {isVerified ? (
                        <span className="text-green-400 flex items-center">
                          <CheckCircle className="w-4 h-4 mr-1" /> Đã xác minh
                        </span>
                      ) : (
                        <span className="text-yellow-400">Chưa xác minh</span>
                      )}
                    </p>
                    <p><span className="text-gray-400">Số dư khả dụng:</span> {getBalance(user.balance).toLocaleString()} VNĐ</p>
                    <p><span className="text-gray-400">Ngày tạo tài khoản:</span> {formatDate(user.createdAt)}</p>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'bank' && (
              <div className="space-y-6">
                <div className="flex justify-between items-center">
                  <h1 className="text-2xl font-bold">Thông tin ngân hàng</h1>
                  <Button
                    variant="outline"
                    onClick={() => setIsEditingBankInfo(!isEditingBankInfo)}
                    className="border-gray-600 text-white hover:bg-gray-700"
                  >
                    {isEditingBankInfo ? 'Hủy' : 'Chỉnh sửa'}
                  </Button>
                </div>

                {isEditingBankInfo ? (
                  <form onSubmit={handleSubmitBankInfo} className="space-y-4 max-w-2xl">
                    <div>
                      <label htmlFor="fullName" className="block text-gray-400 mb-1">Tên chủ tài khoản</label>
                      <input
                        id="fullName"
                        name="accountHolder"
                        type="text"
                        value={bankForm.accountHolder}
                        onChange={handleBankFormChange}
                        className="w-full bg-gray-800 border border-gray-700 rounded p-2 text-white"
                        required 
                      />
                    </div>
                    <div>
                      <label htmlFor="bankType" className="block text-gray-400 mb-1">Loại tài khoản</label>
                      <select
                        id="bankType"
                        name="bankType"
                        value={bankForm.bankType}
                        onChange={handleBankFormChange}
                        className="w-full bg-gray-800 border border-gray-700 rounded p-2 text-white"
                        required
                      >
                        <option value="">Chọn loại tài khoản</option>
                        <option value="Ngân hàng">Ngân hàng</option>
                        <option value="Ví điện tử">Ví điện tử</option>
                      </select>
                    </div>
                    <div>
                      <label htmlFor="bankName" className="block text-gray-400 mb-1">Tên ngân hàng/Ví điện tử</label>
                      <input
                        id="bankName"
                        name="bankName"
                        type="text"
                        value={bankForm.bankName}
                        onChange={handleBankFormChange}
                        className="w-full bg-gray-800 border border-gray-700 rounded p-2 text-white"
                        required 
                      />
                    </div>
                    <div>
                      <label htmlFor="accountNumber" className="block text-gray-400 mb-1">Số tài khoản/Số điện thoại</label>
                      <input
                        id="accountNumber"
                        name="accountNumber"
                        type="text"
                        value={bankForm.accountNumber}
                        onChange={handleBankFormChange}
                        className="w-full bg-gray-800 border border-gray-700 rounded p-2 text-white"
                        required 
                      />
                    </div>
                    <div className="flex space-x-3 pt-2">
                      <Button type="submit" disabled={isSaving}>
                        {isSaving ? (
                          <>
                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                            Đang lưu...
                          </>
                        ) : 'Lưu thay đổi'}
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
                        className="border-gray-600 text-white hover:bg-gray-700"
                        onClick={() => setIsEditingBankInfo(false)}
                      >
                        Hủy
                      </Button>
                    </div>
                  </form>
                ) : (
                  <div className="bg-gray-800/50 p-6 rounded-lg max-w-2xl">
                    <div className="space-y-3">
                      <p><span className="text-gray-400">Tên chủ tài khoản:</span> {bankForm.accountHolder || 'Chưa cập nhật'}</p>
                      <p><span className="text-gray-400">Loại tài khoản:</span> {bankForm.bankType || 'Chưa cập nhật'}</p>
                      <p><span className="text-gray-400">Tên ngân hàng/Ví điện tử:</span> {bankForm.bankName || 'Chưa cập nhật'}</p>
                      <p><span className="text-gray-400">Số tài khoản/SĐT:</span> {bankForm.accountNumber || 'Chưa cập nhật'}</p>
                      <p>
                        <span className="text-gray-400">Trạng thái xác minh:</span>{' '}
                        {bankForm.verified ? (
                          <span className="text-green-400">Đã xác minh</span>
                        ) : (
                          <span className="text-yellow-400">Chưa xác minh</span>
                        )}
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )}
  
            {activeTab === 'verify' && (
              <div className="space-y-6">
                <div>
                  <h1 className="text-2xl font-bold mb-2">Xác minh danh tính</h1>
                  <p className="text-gray-400">Vui lòng tải lên ảnh chụp 2 mặt CMND/CCCD của bạn</p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {/* Front ID Card */}
                  <div className="bg-gray-800/50 rounded-lg p-6">
                    <h3 className="font-medium mb-4">Mặt trước CMND/CCCD</h3>
                    {verificationStatus.cccdFront ? (
                      <div className="relative">
                        <img 
                          src={verificationStatus.cccdFront} 
                          alt="Mặt trước CMND/CCCD"
                          className="w-full h-auto rounded border border-gray-700"
                        />
                        {uploadStatus.front && (
                          <div className={`mt-2 text-sm ${uploadStatus.front.success ? 'text-green-400' : 'text-red-400'}`}>
                            {uploadStatus.front.success ? (
                              <span className="flex items-center">
                                <CheckCircle className="w-4 h-4 mr-1" />
                                {uploadStatus.front.message}
                              </span>
                            ) : (
                              <span className="flex items-center">
                                <XCircle className="w-4 h-4 mr-1" />
                                {uploadStatus.front.message}
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="border-2 border-dashed border-gray-700 rounded-lg p-6 text-center">
                        <input
                          type="file"
                          id="frontId"
                          accept="image/*"
                          className="hidden"
                          onChange={(e) => handleFileChange(e, 'front')}
                        />
                        <label
                          htmlFor="frontId"
                          className="flex flex-col items-center justify-center cursor-pointer p-6"
                        >
                          <UploadCloud className="w-12 h-12 text-gray-500 mb-2" />
                          <p className="text-gray-400">Tải lên mặt trước CMND/CCCD</p>
                          <p className="text-xs text-gray-500 mt-1">JPG, PNG (tối đa 5MB)</p>
                        </label>
                        {frontIdFile && (
                          <Button
                            onClick={() => handleUpload('front')}
                            disabled={isUploading}
                            className="mt-4 w-full"
                          >
                            {isUploading ? (
                              <>
                                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                Đang tải lên...
                              </>
                            ) : 'Xác nhận tải lên'}
                          </Button>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Back ID Card */}
                  <div className="bg-gray-800/50 rounded-lg p-6">
                    <h3 className="font-medium mb-4">Mặt sau CMND/CCCD</h3>
                    {verificationStatus.cccdBack ? (
                      <div className="relative">
                        <img 
                          src={verificationStatus.cccdBack} 
                          alt="Mặt sau CMND/CCCD"
                          className="w-full h-auto rounded border border-gray-700"
                        />
                        {uploadStatus.back && (
                          <div className={`mt-2 text-sm ${uploadStatus.back.success ? 'text-green-400' : 'text-red-400'}`}>
                            {uploadStatus.back.success ? (
                              <span className="flex items-center">
                                <CheckCircle className="w-4 h-4 mr-1" />
                                {uploadStatus.back.message}
                              </span>
                            ) : (
                              <span className="flex items-center">
                                <XCircle className="w-4 h-4 mr-1" />
                                {uploadStatus.back.message}
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="border-2 border-dashed border-gray-700 rounded-lg p-6 text-center">
                        <input
                          type="file"
                          id="backId"
                          accept="image/*"
                          className="hidden"
                          onChange={(e) => handleFileChange(e, 'back')}
                        />
                        <label
                          htmlFor="backId"
                          className="flex flex-col items-center justify-center cursor-pointer p-6"
                        >
                          <UploadCloud className="w-12 h-12 text-gray-500 mb-2" />
                          <p className="text-gray-400">Tải lên mặt sau CMND/CCCD</p>
                          <p className="text-xs text-gray-500 mt-1">JPG, PNG (tối đa 5MB)</p>
                        </label>
                        {backIdFile && (
                          <Button
                            onClick={() => handleUpload('back')}
                            disabled={isUploading}
                            className="mt-4 w-full"
                          >
                            {isUploading ? (
                              <>
                                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                Đang tải lên...
                              </>
                            ) : 'Xác nhận tải lên'}
                          </Button>
                        )}
                      </div>
                    )}
                  </div>
                </div>

                <div className="mt-8 bg-blue-900/20 border border-blue-800/50 rounded-lg p-4 text-sm text-blue-200">
                  <h4 className="font-medium mb-2">Hướng dẫn tải ảnh:</h4>
                  <ul className="space-y-1 text-xs">
                    <li>• Ảnh phải rõ nét, không bị mờ, không bị che khuất</li>
                    <li>• Chụp đầy đủ 4 góc CMND/CCCD</li>
                    <li>• Đảm bảo thông tin trên CMND/CCCD dễ đọc</li>
                    <li>• Kích thước tối đa: 5MB/ảnh</li>
                  </ul>
                </div>

                <div className="p-4 bg-yellow-900/20 border border-yellow-800/50 rounded-lg">
                  <h4 className="font-medium text-yellow-300 mb-2">Lưu ý quan trọng:</h4>
                  <ul className="text-sm text-yellow-200 space-y-1">
                    <li>• Thông tin của bạn sẽ được bảo mật và chỉ sử dụng cho mục đích xác minh danh tính</li>
                    <li>• Thời gian xử lý: Thông thường từ 1-3 ngày làm việc</li>
                    <li>• Vui lòng đảm bảo thông tin trên CMND/CCCD rõ ràng và dễ đọc</li>
                  </ul>
                </div>
              </div>
            )}

            {activeTab === 'password' && (
              <div className="space-y-6">
                <h1 className="text-2xl font-bold">Đổi mật khẩu</h1>
                
                <div className="bg-gray-800/50 p-6 rounded-lg max-w-2xl">
                  <form onSubmit={handleSubmitPassword} className="space-y-4">
                    <div>
                      <label htmlFor="currentPassword" className="block text-gray-400 mb-1">Mật khẩu hiện tại</label>
                      <input
                        id="currentPassword"
                        name="currentPassword"
                        type="password"
                        value={passwordForm.currentPassword}
                        onChange={handlePasswordChange}
                        className="w-full bg-gray-800 border border-gray-700 rounded p-2 text-white"
                        required
                      />
                    </div>
                    <div>
                      <label htmlFor="newPassword" className="block text-gray-400 mb-1">Mật khẩu mới</label>
                      <input
                        id="newPassword"
                        name="newPassword"
                        type="password"
                        value={passwordForm.newPassword}
                        onChange={handlePasswordChange}
                        className="w-full bg-gray-800 border border-gray-700 rounded p-2 text-white"
                        required
                        minLength={6}
                      />
                      {passwordError && <p className="mt-1 text-sm text-red-400">{passwordError}</p>}
                    </div>
                    <Button type="submit" className="mt-4 bg-blue-600 hover:bg-blue-700" disabled={isSaving}>
                      {isSaving ? (
                        <>
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          Đang xử lý...
                        </>
                      ) : (
                        'Cập nhật mật khẩu'
                      )}
                    </Button>
                  </form>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};