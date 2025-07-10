"use client";

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/useAuth';
import { useToast } from "@/components/ui/use-toast";
import { generateSessionId, parseSessionId } from '@/lib/sessionUtils';
import { Loader2, AlertCircle, RefreshCw, ArrowDown, ArrowUp, ChevronDown, Plus, Minus } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from '@/components/ui/dialog';
import RightColumn from './RightColumn';
import LiquidityTable from '@/components/LiquidityTable';

// Types
export interface TradeHistoryRecord {
  id: string;
  sessionId: string;
  direction: "UP" | "DOWN";
  amount: number;
  status: "pending" | "completed";
  result: "win" | "lose" | null;
  profit: number;
  createdAt: string;
}

interface TradeResult {
  status: "idle" | "win" | "lose";
  direction?: "UP" | "DOWN";
  profit?: number;
  amount?: number;
}

const QUICK_AMOUNTS = [100000, 1000000, 5000000, 10000000, 30000000, 50000000, 100000000, 200000000];
const SESSION_DURATION = 60; // 60 seconds per session
const RESULT_DELAY = 5; // 5 seconds delay for result

const formatCurrency = (value: number): string => {
  return new Intl.NumberFormat('vi-VN', { style: 'currency', currency: 'VND' }).format(value);
};

const formatAmount = (value: string): string => {
  const num = parseFloat(value);
  return isNaN(num) ? '' : num.toLocaleString('vi-VN');
};

export default function TradePage() {
  const { user, isLoading: authLoading, refreshUser, isAuthenticated } = useAuth();
  const router = useRouter();
  const { toast } = useToast();
  
  // State
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [balance, setBalance] = useState<number>(0);
  const [isRefreshingBalance, setIsRefreshingBalance] = useState(false);
  
  // Track new trade for error handling
  const newTradeRef = useRef<{ id: string; amount: number } | null>(null);
  const [tradeHistory, setTradeHistory] = useState<TradeHistoryRecord[]>([]);
  const [currentSessionId, setCurrentSessionId] = useState<string>(() => {
    // Khởi tạo sessionId khi component mount
    if (typeof window !== 'undefined') {
      return generateSessionId();
    }
    return '';
  });
  const [timeLeft, setTimeLeft] = useState<number>(SESSION_DURATION);
  const [amount, setAmount] = useState<string>('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isConfirming, setIsConfirming] = useState(false);
  const [selectedAction, setSelectedAction] = useState<"UP" | "DOWN" | null>(null);
  const [tradeResult, setTradeResult] = useState<TradeResult>({ status: "idle" });

  // Update countdown timer to show seconds remaining in current minute (59 to 0)
  useEffect(() => {
    if (!authLoading && !user) {
      router.replace('/auth/login');
      toast({ variant: 'destructive', title: 'Vui lòng đăng nhập để sử dụng tính năng này' });
      return;
    }

    const updateCountdown = () => {
      const now = new Date();
      const seconds = now.getSeconds();
      // Calculate seconds remaining in the current minute (59 to 0)
      const secondsRemaining = 59 - seconds;
      setTimeLeft(secondsRemaining);
      
      // If we're at the last second, check for session update
      if (secondsRemaining <= 1) {
        // Small delay to ensure we're into the next minute
        setTimeout(() => {
          const newNow = new Date();
          const newSessionId = generateSessionId(newNow);
          if (newSessionId !== currentSessionId) {
            setCurrentSessionId(newSessionId);
          }
        }, 1000);
      }
    };

    // Update immediately
    updateCountdown();
    
    // Set up interval to update every second
    const timer = setInterval(updateCountdown, 1000);

    return () => {
      clearInterval(timer);
    };
  }, [authLoading, user, router, toast, currentSessionId]);
  
  // Fetch current session from server periodically with retry logic
  useEffect(() => {
    if (!isAuthenticated()) return;
    
    let retryCount = 0;
    const MAX_RETRIES = 3;
    const RETRY_DELAY = 2000; // 2 seconds
    
    const fetchCurrentSession = async (isRetry = false) => {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout
        
        const response = await fetch('/api/sessions/current', {
          signal: controller.signal,
          cache: 'no-store',
          headers: {
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
          }
        });
        
        clearTimeout(timeoutId);
        
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const sessions = await response.json();
        retryCount = 0; // Reset retry count on success
        
        if (sessions && sessions.length > 0) {
          const currentSession = sessions[0];
          const newSessionId = currentSession.sessionId;
          
          if (newSessionId !== currentSessionId) {
            setCurrentSessionId(newSessionId);
          }
        }
      } catch (error) {
        console.error('Error fetching current session:', error);
        
        // Only log to console if not a retry attempt
        if (!isRetry) {
          console.error('Error details:', {
            name: error.name,
            message: error.message,
            stack: error.stack
          });
        }
        
        // Implement exponential backoff for retries
        if (retryCount < MAX_RETRIES) {
          retryCount++;
          const delay = RETRY_DELAY * Math.pow(2, retryCount - 1);
          console.log(`Retrying in ${delay}ms... (Attempt ${retryCount}/${MAX_RETRIES})`);
          
          setTimeout(() => {
            fetchCurrentSession(true);
          }, delay);
        } else {
          console.error('Max retries reached for session fetch');
          // Optionally show a user-friendly error message
          toast({
            variant: 'destructive',
            title: 'Kết nối mạng không ổn định',
            description: 'Đang thử kết nối lại...',
            duration: 5000
          });
        }
      }
    };

    // Initial fetch
    fetchCurrentSession();
    
    // Then check every 10 seconds, but only if we're not in a retry state
    const sessionCheckInterval = setInterval(() => {
      if (retryCount === 0) {
        fetchCurrentSession();
      }
    }, 10000);
    
    return () => {
      clearInterval(sessionCheckInterval);
    };
  }, [currentSessionId, isAuthenticated, toast]);

  // Handle session ID changes and cleanup
  useEffect(() => {
    if (!currentSessionId) return;
    
    // Reset trade result when session changes
    setTradeResult({ status: 'idle' });
    
    // Mark all previous trades as completed
    setTradeHistory(prev => 
      prev.map(trade => 
        trade.status === 'pending' && trade.sessionId !== currentSessionId 
          ? { ...trade, status: 'completed' as const }
          : trade
      )
    );
    
    // Refresh user balance when session changes
    const refreshBalanceOnSessionChange = async () => {
      try {
        await refreshUser();
      } catch (error) {
        console.error('Error refreshing balance on session change:', error);
      }
    };
    
    refreshBalanceOnSessionChange();
    
  }, [currentSessionId, refreshUser]);

  // Track which trades have been processed to prevent duplicate updates
  const processedTradesRef = useRef<Set<string>>(new Set());

  // Get trade result from admin API
  const getAdminResult = async (sessionId: string): Promise<'UP' | 'DOWN' | null> => {
    try {
      const response = await fetch(`/api/trades/admin-result?sessionId=${sessionId}`);
      const data = await response.json();
      
      if (data.success && data.result) {
        return data.result as 'UP' | 'DOWN';
      }
      return null;
    } catch (error) {
      console.error('Lỗi khi lấy kết quả từ admin:', error);
      return null;
    }
  };

  // Save trade result to database
  const saveTradeResult = async (tradeId: string, result: 'win' | 'lose', profit: number) => {
    try {
      const response = await fetch('/api/trades/result', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          tradeId,
          result,
          profit,
        }),
      });

      if (!response.ok) {
        throw new Error('Lỗi khi lưu kết quả giao dịch');
      }
    } catch (error) {
      console.error('Lỗi khi lưu kết quả giao dịch:', error);
      toast({
        title: 'Lỗi',
        description: 'Không thể lưu kết quả giao dịch. Vui lòng thử lại.',
        variant: 'destructive',
      });
    }
  };

  // Handle trade results after session ends
  useEffect(() => {
    if (timeLeft !== 0) return; // Only run when timeLeft is 0 (session ended)
    
    // Find all pending trades for the current session that haven't been processed yet
    const pendingTrades = tradeHistory.filter(
      trade => 
        trade.status === 'pending' && 
        trade.sessionId === currentSessionId &&
        !processedTradesRef.current.has(trade.id)
    );

    if (pendingTrades.length === 0) return;

    // Mark these trades as being processed
    pendingTrades.forEach(trade => processedTradesRef.current.add(trade.id));

    let isMounted = true;

    const processTradeResults = async () => {
      if (!isMounted) return;
      
      // Process each trade result
      for (const trade of pendingTrades) {
        if (!isMounted) break;
        
        try {
          // Get result from admin
          const adminResult = await getAdminResult(trade.sessionId);
          
          if (!adminResult) {
            console.error(`Không tìm thấy kết quả cho phiên ${trade.sessionId}`);
            continue; // Skip this trade if no admin result
          }
          
          const isWin = trade.direction === adminResult;
          const profit = isWin ? Math.floor(trade.amount * 0.9) : 0; // 90% payout
          
          // Save result to database
          await saveTradeResult(trade.id, isWin ? 'win' : 'lose', profit);
          
          // Update local state
          if (isMounted) {
            setTradeHistory(prev => 
              prev.map(t => 
                t.id === trade.id 
                  ? {
                      ...t,
                      status: 'completed',
                      result: isWin ? 'win' : 'lose',
                      profit,
                    }
                  : t
              )
            );
            
            // Show result toast
            setTradeResult({
              status: isWin ? 'win' : 'lose',
              direction: trade.direction,
              profit,
              amount: trade.amount,
            });
            
            // Update balance optimistically
            setBalance(prev => isWin ? prev + trade.amount + profit : prev);
          }
          
          // Refresh user balance from server to ensure accuracy
          if (isMounted) {
            try {
              await refreshUser();
              // Double check balance after refresh
              const updatedBalance = await refreshBalance();
              if (isMounted) {
                setBalance(updatedBalance);
              }
            } catch (refreshError) {
              console.error('Lỗi khi làm mới số dư sau khi có kết quả giao dịch:', refreshError);
              // Schedule a retry
              setTimeout(() => {
                if (isMounted) refreshUser().catch(console.error);
              }, 5000);
            }
          }
        } catch (error) {
          console.error('Lỗi khi xử lý kết quả giao dịch:', error);
          // If there was an error, refresh the balance to get the correct state
          if (isMounted) {
            await refreshUser();
          }
        }
      }
    };

    const timeout = setTimeout(processTradeResults, RESULT_DELAY * 1000);
    
    return () => {
      isMounted = false;
      clearTimeout(timeout);
    };
  }, [timeLeft, currentSessionId, tradeHistory, refreshUser, getAdminResult, saveTradeResult]);

  // Handle amount changes
  const addAmount = useCallback((value: number) => {
    setAmount(prev => {
      const current = parseFloat(prev) || 0;
      const newAmount = Math.max(100000, current + value);
      return newAmount.toString();
    });
  }, []);

  // Handle trade action
  const handleAction = useCallback(async (direction: "UP" | "DOWN") => {
    const amountValue = parseFloat(amount);
    if (!amount || isNaN(amountValue) || amountValue < 100000) {
      toast({
        title: 'Lỗi',
        description: 'Số tiền phải lớn hơn hoặc bằng 100,000 VND',
        variant: 'destructive',
      });
      return;
    }
    
    // Always check balance from server before placing order
    try {
      const currentBalance = await refreshBalance();
      if (amountValue > currentBalance) {
        toast({
          title: 'Lỗi',
          description: 'Số dư không đủ để đặt lệnh',
          variant: 'destructive',
        });
        return;
      }
    } catch (error) {
      console.error('Lỗi khi kiểm tra số dư:', error);
      toast({
        title: 'Lỗi',
        description: 'Không thể kiểm tra số dư. Vui lòng thử lại.',
        variant: 'destructive',
      });
      return;
    }
    setSelectedAction(direction);
    setIsConfirming(true);
  }, [amount, balance, toast]);

  // Refresh balance from server
  const refreshBalance = useCallback(async () => {
    try {
      setIsRefreshingBalance(true);
      const response = await fetch('/api/users/me', {
        credentials: 'include',
        headers: {
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache',
          'Expires': '0'
        }
      });
      
      if (response.ok) {
        const userData = await response.json();
        if (userData?.balance?.available !== undefined) {
          setBalance(userData.balance.available);
          return userData.balance.available;
        }
      }
      return balance;
    } catch (error) {
      console.error('Lỗi khi làm mới số dư:', error);
      return balance;
    } finally {
      setIsRefreshingBalance(false);
    }
  }, [balance]);

  // Update balance when user data changes
  useEffect(() => {
    if (user?.balance?.available !== undefined) {
      setBalance(user.balance.available);
    } else if (isAuthenticated()) {
      refreshBalance();
    }
  }, [user?.balance?.available, isAuthenticated, refreshBalance]);

  // Confirm trade
  const confirmTrade = useCallback(async () => {
    if (!selectedAction || !amount) return;

    setIsSubmitting(true);
    setIsConfirming(false);

    let amountValue = 0;
    let newTradeId = '';
    
    try {
      // Refresh balance before placing order
      const currentBalance = await refreshBalance();
      amountValue = Number(amount);
      
      if (currentBalance < amountValue) {
        toast({
          title: 'Lỗi',
          description: 'Số dư không đủ để đặt lệnh',
          variant: 'destructive',
        });
        return;
      }

      const newTrade: TradeHistoryRecord = {
        id: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
        sessionId: currentSessionId,
        direction: selectedAction,
        amount: amountValue,
        status: 'pending',
        result: null,
        profit: 0,
        createdAt: new Date().toISOString(),
      };
      
      newTradeId = newTrade.id;
      // Store the new trade in ref for error handling
      newTradeRef.current = { id: newTradeId, amount: amountValue };

      // Update local state optimistically
      setTradeHistory(prev => [newTrade, ...prev]);
      setBalance(prev => prev - amountValue);
      setAmount('');
      setSelectedAction(null);

      // Save to server
      const response = await fetch('/api/trades', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          sessionId: currentSessionId,
          direction: selectedAction,
          amount: amountValue,
        }),
      });

      if (!response.ok) {
        throw new Error('Lỗi khi lưu giao dịch');
      }

      // Refresh user data to ensure balance is in sync
      try {
        await refreshUser();
        // Double check balance after refresh
        const updatedBalance = await refreshBalance();
        setBalance(updatedBalance);
      } catch (refreshError) {
        console.error('Lỗi khi làm mới số dư:', refreshError);
        // Don't show error to user, just log it
      }
      
      toast({
        title: 'Thành công',
        description: `Đã đặt lệnh ${selectedAction === 'UP' ? 'LÊN' : 'XUỐNG'} thành công`,
      });
    } catch (error) {
      console.error('Lỗi khi đặt lệnh:', error);
      toast({
        title: 'Lỗi',
        description: 'Đã xảy ra lỗi khi đặt lệnh. Vui lòng thử lại.',
        variant: 'destructive',
      });
      
      // Revert optimistic update on error
      if (newTradeRef.current) {
        setTradeHistory(prev => prev.filter(trade => trade.id !== newTradeRef.current?.id));
        setBalance(prev => prev + amountValue);
      }
    } finally {
      setIsSubmitting(false);
      newTradeRef.current = null;
    }
  }, [selectedAction, amount, currentSessionId, toast]);

  // Loading state
  if (isLoading || authLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <Loader2 className="h-8 w-8 animate-spin text-blue-500" />
        <span className="ml-2">Đang tải dữ liệu...</span>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen p-4">
        <AlertCircle className="h-12 w-12 text-red-500 mb-4" />
        <h2 className="text-xl font-semibold mb-2">Đã xảy ra lỗi</h2>
        <p className="text-gray-600 mb-4 text-center">{error}</p>
        <Button onClick={() => window.location.reload()}>
          <RefreshCw className="mr-2 h-4 w-4" /> Tải lại trang
        </Button>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900">
      <div className="p-4 md:p-8">
        <Dialog
          open={tradeResult.status === "win" || tradeResult.status === "lose"}
          onOpenChange={(open) => !open && setTradeResult({ status: "idle" })}
        >
          <DialogContent className="sm:max-w-[425px] bg-gray-800 border-green-500">
            <DialogHeader>
              <DialogTitle className={`text-2xl text-center ${tradeResult.status === "win" ? "text-green-500" : "text-red-500"}`}>
                {tradeResult.status === "win" ? "Chúc mừng bạn đã thắng!" : "Rất tiếc, bạn đã thua"}
              </DialogTitle>
              <DialogDescription className="text-center text-white">
                {tradeResult.profit && tradeResult.profit > 0 ? "+" : ""}
                {tradeResult.profit ? formatCurrency(tradeResult.profit) : 0} VND
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-4">
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div className="text-gray-400">Lệnh:</div>
                <div className="text-white">
                  {tradeResult.direction === "UP" ? "LÊN" : tradeResult.direction === "DOWN" ? "XUỐNG" : "-"}
                </div>
                <div className="text-gray-400">Số tiền:</div>
                <div className="text-white">
                  {tradeResult.amount ? formatCurrency(tradeResult.amount) : 0} VND
                </div>
                <div className="text-gray-400">Lợi nhuận:</div>
                <div className={`font-bold ${(tradeResult.profit || 0) >= 0 ? "text-green-500" : "text-red-600"}`}>
                  {tradeResult.profit && tradeResult.profit > 0 ? "+" : ""}
                  {tradeResult.profit ? formatCurrency(tradeResult.profit) : 0} VND
                </div>
              </div>
            </div>
            <DialogFooter>
              <Button
                type="button"
                className="w-full bg-green-600 hover:bg-green-700"
                onClick={() => setTradeResult({ status: "idle" })}
              >
                Đóng
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        <Dialog open={isConfirming} onOpenChange={setIsConfirming}>
          <DialogContent className="sm:max-w-[425px] bg-gray-800">
            <DialogHeader>
              <DialogTitle className="text-white text-center">
                Phiên hiện tại <span className="text-red-500">{currentSessionId || 'N/A'}</span>
              </DialogTitle>
            </DialogHeader>
            <DialogDescription className="text-gray-300 text-center">
              XÁC NHẬN
            </DialogDescription>
            <DialogFooter className="flex gap-2">
              <Button
                type="button"
                variant="outline"
                className="flex-1 bg-red-600 hover:bg-red-700 text-white"
                onClick={() => setIsConfirming(false)}
              >
                Hủy
              </Button>
              <Button
                type="button"
                className={`flex-1 ${selectedAction === "UP" ? "bg-green-600 hover:bg-green-700" : "bg-red-600 hover:bg-red-700"}`}
                onClick={confirmTrade}
              >
                Xác nhận
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        <div className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-8 lg:order-2 order-1">
            <RightColumn
              isLoading={isLoading}
              tradeHistory={tradeHistory}
              formatCurrency={formatCurrency}
            />
          </div>

          <div className="lg:col-span-4 space-y-6 lg:order-1 order-2">
            <Card className="bg-white border border-gray-300 rounded-md shadow">
              <CardHeader>
                <div className="flex items-center space-x-2">
                  <ChevronDown className="h-4 w-4 text-gray-700" />
                  <CardTitle className="text-gray-900 text-base font-medium">Số dư</CardTitle>
                </div>
              </CardHeader>
              <CardContent className="py-6 px-4">
                <div className="flex items-center justify-between text-gray-900 text-lg font-semibold uppercase">
                  <span>SỐ DƯ:</span>
                  <span>{formatCurrency(balance || 0)} VND</span>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-white border border-gray-300 rounded-md shadow">
              <CardHeader>
                <div className="flex items-center space-x-2">
                  <ChevronDown className="h-4 w-4 text-gray-700" />
                  <CardTitle className="text-gray-900 text-base font-medium">Đặt lệnh</CardTitle>
                  <span className="bg-green-600 text-white text-xs font-semibold px-2 py-1 rounded ml-auto">
                    Phiên: {currentSessionId || 'N/A'}
                  </span>
                </div>
              </CardHeader>
              <CardContent>
                <div className="mb-4">
                  <div className="flex justify-between items-center mb-2">
                    <label htmlFor="amount" className="text-sm text-gray-400">
                      Số tiền (VND)
                    </label>
                    <span className="text-xs text-gray-400">Tối thiểu: {formatCurrency(100000)}</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Button variant="outline" size="icon" onClick={() => addAmount(-100000)}>
                      <Minus className="h-4 w-4" />
                    </Button>
                    <Input
                      id="amount"
                      type="text"
                      value={formatAmount(amount)}
                      onChange={(e) => {
                        const raw = e.target.value.replace(/,/g, "");
                        if (/^\d*$/.test(raw)) setAmount(raw);
                      }}
                      placeholder="Nhập số tiền"
                    />
                    <Button variant="outline" size="icon" onClick={() => addAmount(100000)}>
                      <Plus className="h-4 w-4" />
                    </Button>
                  </div>
                  <div className="grid grid-cols-3 gap-2 mt-2">
                    {QUICK_AMOUNTS.map((value) => (
                      <Button
                        key={value}
                        type="button"
                        variant="outline"
                        size="sm"
                        className="text-sm font-semibold bg-white hover:bg-gray-100"
                        onClick={() => addAmount(value)}
                      >
                        {value >= 1000000 ? `+${value / 1000000}M` : `+${value / 1000}K`}
                      </Button>
                    ))}
                  </div>
                </div>
                <div className="space-y-1 mb-4 text-sm text-gray-900">
                  <div className="flex justify-between">
                    <span>Ngày:</span>
                    <span>{new Date().toLocaleString('en-US', { year: 'numeric', month: '2-digit', day: '2-digit' })}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Giờ:</span>
                    <span>{new Date().toLocaleString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span>
                  </div>
                  <div className="flex justify-between font-semibold">
                    <span>Phiên hiện tại:</span>
                    <span>{currentSessionId || 'N/A'}</span>
                  </div>
                </div>
                <div className="mb-4">
                  <div className="border border-red-600 rounded bg-gray-100 text-center py-3">
                    <div className="text-sm text-gray-900">Hãy đặt lệnh:</div>
                    <div className="text-xl font-bold text-red-600">{String(timeLeft).padStart(2, '0')}s</div>
                  </div>
                </div>
                <div className="space-y-3">
                  <Button
                    type="button"
                    className="w-full h-14 bg-green-600 hover:bg-green-700 text-lg font-bold flex items-center justify-center"
                    onClick={() => handleAction("UP")}
                    disabled={isLoading || !amount || isSubmitting}
                  >
                    LÊN <ArrowUp className="h-5 w-5 ml-2" />
                  </Button>
                  <Button
                    type="button"
                    className="w-full h-14 bg-red-600 hover:bg-red-700 text-lg font-bold flex items-center justify-center"
                    onClick={() => handleAction("DOWN")}
                    disabled={isLoading || !amount || isSubmitting}
                  >
                    XUỐNG <ArrowDown className="h-5 w-5 ml-2" />
                  </Button>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-white border-gray-300 rounded-md shadow">
              <CardHeader>
                <CardTitle className="text-gray-900">Cập nhật</CardTitle>
              </CardHeader>
              <CardContent>
                <LiquidityTable />
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
}