'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/useAuth';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast } from '@/components/ui/use-toast';
import useSWR from 'swr';
import { Upload } from 'lucide-react';

export default function DepositPage() {
  const { user, isLoading, isAuthenticated } = useAuth();
  const [authToken, setAuthToken] = useState<string | null>(null);
  const router = useRouter();
  const { toast } = useToast();
  const [amount, setAmount] = useState('');
  const [bill, setBill] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [billUrl, setBillUrl] = useState<string | null>(null);
  const [selectedBank, setSelectedBank] = useState('');
  const [isConfirmed, setIsConfirmed] = useState(false);

  // Get settings with proper authentication
  const { data: settings, error: settingsError } = useSWR(
    user ? '/api/admin/settings' : null,
    async (url: string) => {
      const res = await fetch(url, { 
        credentials: 'include' // This will include the session cookie
      });
      if (!res.ok) throw new Error('Failed to fetch settings');
      return res.json();
    }
  );

  useEffect(() => {
    if (!isLoading && !isAuthenticated()) {
      toast({ variant: 'destructive', title: 'Lỗi', description: 'Vui lòng đăng nhập' });
      router.push('/login');
    }
  }, [user, isLoading, isAuthenticated, router, toast]);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setBill(file);
      handleUploadFile(file);
    }
  };

  const handleUploadFile = async (file: File) => {
    setIsUploading(true);
    setBillUrl(null);
    
    try {
      const formData = new FormData();
      formData.append('file', file);
      
      const response = await fetch('/api/upload', {
        method: 'POST',
        credentials: 'include', // Include session cookie
        body: formData,
      });
      
      if (!response.ok) {
        throw new Error('Upload thất bại');
      }
      
      const data = await response.json();
      setBillUrl(data.url);
      toast({
        title: 'Thành công',
        description: 'Tải lên ảnh thành công',
      });
    } catch (error) {
      console.error('Lỗi khi tải lên ảnh:', error);
      toast({
        variant: 'destructive',
        title: 'Lỗi',
        description: 'Không thể tải lên ảnh. Vui lòng thử lại.',
      });
      setBill(null);
    } finally {
      setIsUploading(false);
    }
  };

  const handleSubmit = async () => {
    if (!amount || !bill || !selectedBank || !isConfirmed) {
      toast({ 
        variant: 'destructive', 
        title: 'Lỗi', 
        description: 'Vui lòng điền đầy đủ thông tin và xác nhận' 
      });
      return;
    }

    if (settings && Number(amount) < settings.minDeposit) {
      toast({ variant: 'destructive', title: 'Lỗi', description: `Số tiền nạp tối thiểu là ${settings.minDeposit.toLocaleString()} đ` });
      return;
    }

    if (!billUrl) {
      toast({ variant: 'destructive', title: 'Lỗi', description: 'Vui lòng đợi ảnh được tải lên hoàn tất' });
      return;
    }

    try {
      const res = await fetch('/api/deposits', {
        method: 'POST',
        credentials: 'include', // Include session cookie
        headers: { 
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          amount: Number(amount),
          bill: billUrl,
          bank: selectedBank,
          confirmed: isConfirmed
        }),
      });
      
      const result = await res.json();
      
      if (res.ok) {
        toast({ title: 'Thành công', description: 'Yêu cầu nạp tiền đã được gửi' });
        setAmount('');
        setBill(null);
        setBillUrl(null);
      } else {
        toast({ variant: 'destructive', title: 'Lỗi', description: result.message || 'Có lỗi xảy ra' });
      }
    } catch (err) {
      console.error('Lỗi khi gửi yêu cầu:', err);
      toast({ 
        variant: 'destructive', 
        title: 'Lỗi', 
        description: 'Không thể gửi yêu cầu. Vui lòng thử lại sau.' 
      });
    }
  };

  if (isLoading || !user) {
    return <div className="flex justify-center items-center h-[60vh] text-gray-600">Đang tải...</div>;
  }

  return (
    <div id="deposit-page" className="min-h-screen bg-gray-900 py-8 px-4">
      <div className="max-w-2xl mx-auto">
        <Card className="bg-gray-800 border-gray-700 shadow-lg rounded-xl">
          <CardHeader className="border-b border-gray-700 p-6">
            <CardTitle className="text-2xl font-semibold text-white">Nạp tiền</CardTitle>
          </CardHeader>
          <CardContent className="p-6 space-y-6">
            <div>
              <h3 className="text-lg font-medium text-gray-300 mb-4">Thông tin ngân hàng nhận tiền</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
                <div>
                  <Label className="text-gray-400">Chọn ngân hàng</Label>
                  <select
                    value={selectedBank}
                    onChange={(e) => setSelectedBank(e.target.value)}
                    className="flex h-10 w-full rounded-md border border-gray-600 bg-gray-700 px-3 py-2 text-sm text-white placeholder-gray-400 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
                    required
                  >
                    <option value="">-- Chọn ngân hàng --</option>
                    {settings?.bankDetails?.map((bank: any, index: number) => (
                      <option key={index} value={bank.bankName}>
                        {bank.bankName} - {bank.accountNumber} ({bank.accountHolder})
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <Label className="text-gray-400">Số tiền nạp (VND)</Label>
                  <Input
                    type="number"
                    value={amount}
                    onChange={(e) => setAmount(e.target.value)}
                    placeholder="Nhập số tiền"
                    className="bg-gray-700 text-white border-gray-600 focus:border-blue-500"
                    min={settings?.depositLimits?.min || 0}
                    max={settings?.depositLimits?.max || 100000000}
                    required
                  />
                </div>
              </div>
              {selectedBank && (
                <div className="bg-gray-700 p-4 rounded-md mb-4">
                  <h4 className="font-medium text-gray-300 mb-2">Thông tin chuyển khoản:</h4>
                  {settings?.bankDetails?.find((b: any) => b.bankName === selectedBank) && (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
                      <div>
                        <p className="text-gray-400">Ngân hàng:</p>
                        <p className="text-white">{
                          settings.bankDetails.find((b: any) => b.bankName === selectedBank)?.bankName
                        }</p>
                      </div>
                      <div>
                        <p className="text-gray-400">Số tài khoản:</p>
                        <p className="text-white">{
                          settings.bankDetails.find((b: any) => b.bankName === selectedBank)?.accountNumber
                        }</p>
                      </div>
                      <div>
                        <p className="text-gray-400">Chủ tài khoản:</p>
                        <p className="text-white">{
                          settings.bankDetails.find((b: any) => b.bankName === selectedBank)?.accountHolder
                        }</p>
                      </div>
                      <div>
                        <p className="text-gray-400">Nội dung chuyển khoản:</p>
                        <p className="text-white font-mono">NAP-{user?.username || 'user'}-{new Date().getTime().toString().slice(-6)}</p>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            <div>
              <Label className="text-gray-400">Tải lên bill chuyển khoản</Label>
              <div className="space-y-2">
                <div className="flex items-center gap-4">
                  <Input
                    type="file"
                    accept="image/*"
                    onChange={handleFileChange}
                    disabled={isUploading}
                    className="bg-gray-700 text-white border-gray-600 focus:border-blue-500 file:bg-gray-600 file:text-white file:hover:bg-gray-500 disabled:opacity-50"
                  />
                </div>
                
                {isUploading && (
                  <div className="flex items-center text-sm text-blue-400">
                    <div className="h-4 w-4 border-2 border-blue-400 border-t-transparent rounded-full animate-spin mr-2"></div>
                    Đang tải lên ảnh...
                  </div>
                )}
                
                {bill && !isUploading && billUrl && (
                  <div className="text-sm text-green-400">
                    ✓ Đã tải lên: {bill.name}
                  </div>
                )}
                
                {bill && !isUploading && !billUrl && (
                  <div className="text-sm text-yellow-400">
                    Lỗi khi tải lên. Vui lòng thử lại.
                  </div>
                )}
              </div>
            </div>
            <div className="flex items-start space-x-2 mt-4">
              <input
                type="checkbox"
                id="confirm-deposit"
                checked={isConfirmed}
                onChange={(e) => setIsConfirmed(e.target.checked)}
                className="mt-1 h-4 w-4 rounded border-gray-600 bg-gray-700 text-blue-500 focus:ring-blue-500"
                required
              />
              <label htmlFor="confirm-deposit" className="text-sm text-gray-300">
                Tôi xác nhận đã chuyển khoản chính xác số tiền và nội dung như trên. Yêu cầu nạp tiền sẽ được xử lý trong vòng 5-15 phút sau khi xác nhận.
              </label>
            </div>

            <Button
              className="w-full bg-green-600 hover:bg-green-700 text-white font-medium py-2.5 rounded-md transition-colors disabled:bg-gray-500 disabled:cursor-not-allowed mt-4"
              onClick={handleSubmit}
              disabled={!amount || !bill || isUploading || !billUrl || !selectedBank || !isConfirmed}
            >
              {isUploading ? (
                <>
                  <div className="h-5 w-5 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></div>
                  Đang xử lý...
                </>
              ) : (
                <>
                  <Upload className="h-5 w-5 mr-2" />
                  Gửi yêu cầu
                </>
              )}
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}