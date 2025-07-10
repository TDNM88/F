"use client";

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/useAuth';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast } from '@/components/ui/use-toast';
import useSWR from 'swr';

export default function WithdrawPage() {
  const { user, token, loading, logout } = useAuth();
  const router = useRouter();
  const { toast } = useToast();
  const [amount, setAmount] = useState('');
  const [bankName, setBankName] = useState('');
  const [accountNumber, setAccountNumber] = useState('');
  const [accountHolder, setAccountHolder] = useState('');

  const { data: settings, error: settingsError } = useSWR(
    token ? '/api/admin/settings' : null,
    url => fetch(url, { headers: { Authorization: `Bearer ${token}` } }).then(res => res.json())
  );

  useEffect(() => {
    if (!loading && !user) {
      toast({ variant: 'destructive', title: 'Lỗi', description: 'Vui lòng đăng nhập' });
      router.push('/login');
    }
    if (user) {
      setBankName(user.bank?.name || '');
      setAccountNumber(user.bank?.accountNumber || '');
      setAccountHolder(user.bank?.accountHolder || '');
    }
  }, [user, loading, router, toast]);

  const handleSubmit = async () => {
    if (!amount || !bankName || !accountNumber || !accountHolder) {
      toast({ variant: 'destructive', title: 'Lỗi', description: 'Vui lòng nhập đầy đủ thông tin' });
      return;
    }

    if (settings && (Number(amount) < settings.minWithdrawal || Number(amount) > settings.maxWithdrawal)) {
      toast({
        variant: 'destructive',
        title: 'Lỗi',
        description: `Số tiền rút phải từ ${settings.minWithdrawal.toLocaleString()} đ đến ${settings.maxWithdrawal.toLocaleString()} đ`,
      });
      return;
    }

    try {
      const res = await fetch('/api/withdrawals', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ amount: Number(amount), bankName, accountNumber, accountHolder }),
      });
      const result = await res.json();
      if (res.ok) {
        toast({ title: 'Thành công', description: 'Yêu cầu rút tiền đã được gửi' });
        setAmount('');
      } else {
        toast({ variant: 'destructive', title: 'Lỗi', description: result.message });
      }
    } catch (err) {
      toast({ variant: 'destructive', title: 'Lỗi', description: 'Không thể gửi yêu cầu' });
    }
  };

  if (loading || !user) {
    return <div className="flex justify-center items-center h-screen text-white">Loading...</div>;
  }

  return (
    <div className="text-white">
      <Card className="bg-gray-800 border-gray-700 max-w-2xl mx-auto">
          <CardHeader>
            <CardTitle className="text-white">Rút tiền</CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            <div>
              <Label className="text-white">Số tiền rút</Label>
              <Input
                type="number"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                placeholder="Số tiền (VND)"
                className="bg-gray-700 text-white"
              />
            </div>
            <div>
              <h3 className="text-lg font-medium text-white mb-4">Thông tin ngân hàng</h3>
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <Label className="text-white">Tên ngân hàng</Label>
                  <Input
                    value={bankName}
                    onChange={(e) => setBankName(e.target.value)}
                    className="bg-gray-700 text-white"
                  />
                </div>
                <div>
                  <Label className="text-white">Số tài khoản</Label>
                  <Input
                    value={accountNumber}
                    onChange={(e) => setAccountNumber(e.target.value)}
                    className="bg-gray-700 text-white"
                  />
                </div>
                <div>
                  <Label className="text-white">Chủ tài khoản</Label>
                  <Input
                    value={accountHolder}
                    onChange={(e) => setAccountHolder(e.target.value)}
                    className="bg-gray-700 text-white"
                  />
                </div>
              </div>
            </div>
            <Button
              className="bg-green-600 hover:bg-green-700"
              onClick={handleSubmit}
              disabled={!amount || !bankName || !accountNumber || !accountHolder}
            >
              Gửi yêu cầu
            </Button>
          </CardContent>
        </Card>
    </div>
  );
}
