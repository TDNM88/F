"use client";

import React, { useState, useEffect, useCallback } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import Image from 'next/image';
import { useAuth } from '@/lib/useAuth';
import { LogOut, User, Wallet, History, Lock, UserCheck, ArrowUpDown, ChevronDown, Menu, X, Loader2, RefreshCw } from 'lucide-react';

const NewHeader = () => {
  const router = useRouter();
  const pathname = usePathname();
  const { user, logout, isLoading, isAuthenticated, refreshUser } = useAuth();
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [isScrolled, setIsScrolled] = useState(false);
  const [supportLink, setSupportLink] = useState('#');
  const [isNavigating, setIsNavigating] = useState(false);
  const [balance, setBalance] = useState<number | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  
  // Fetch support link and user balance from database
  const fetchData = useCallback(async () => {
    try {
      setIsRefreshing(true);
      
      // Fetch support link in parallel with user refresh
      const [settingsRes] = await Promise.all([
        fetch('/api/settings'),
        isAuthenticated() ? refreshUser() : Promise.resolve()
      ]);
      
      if (settingsRes.ok) {
        const data = await settingsRes.json();
        if (data.settings?.telegramSupport) {
          setSupportLink(data.settings.telegramSupport);
        }
      }
      
      // Update balance from the refreshed user data
      if (isAuthenticated() && user?.balance?.available !== undefined) {
        setBalance(user.balance.available);
      }
    } catch (error) {
      console.error('Error fetching data:', error);
    } finally {
      setIsRefreshing(false);
    }
  }, [isAuthenticated, refreshUser, user?.balance?.available]);
  
  // Initial data fetch
  useEffect(() => {
    fetchData();
  }, [fetchData]);
  
  // Update balance when user data changes
  useEffect(() => {
    if (user?.balance?.available !== undefined) {
      setBalance(user.balance.available);
    }
  }, [user?.balance?.available]);
  
  // Close mobile menu when route changes
  useEffect(() => {
    setIsMenuOpen(false);
    
    // Reset navigation state when path changes
    setIsNavigating(false);
  }, [pathname]);
  
  const handleLogout = async () => {
    try {
      await logout();
      router.push('/');
      router.refresh(); // Ensure the page refreshes to update auth state
    } finally {
      setIsNavigating(false);
    }
  };

  const handleNavigation = async (path: string) => {
    // Prevent multiple simultaneous navigations
    if (isNavigating) return;
    
    // Don't navigate if already on the same path
    if (pathname === path) {
      setIsMenuOpen(false);
      return;
    }
    
    // Close mobile menu if open
    setIsMenuOpen(false);
    
    // Define public paths that don't require authentication
    const publicPaths = [
      '/',
      '/login', 
      '/register', 
      '/auth/login', 
      '/auth/register',
      '/forgot-password',
      '/reset-password',
      '/_next',
      '/api',
      '/favicon.ico',
      '/images',
      '/icons'
    ];
    
    // Check if the target path is public
    const isPublicPath = publicPaths.some(p => 
      path === p || path.startsWith(`${p}/`)
    );
    
    // Get the first segment of the target path
    const targetSection = path.split('/').filter(Boolean)[0] || '/';
    
    // Set navigation state
    setIsNavigating(true);
    
    try {
      // If it's a public path, navigate directly
      if (isPublicPath) {
        await router.push(path);
        return;
      }
      
      // For protected paths, check authentication first
      const isAuth = isAuthenticated();
      
      if (!isAuth) {
        // If not authenticated, redirect to login with return URL
        const loginUrl = new URL('/login', window.location.origin);
        loginUrl.searchParams.set('returnUrl', path);
        window.location.href = loginUrl.toString();
        return;
      }
      
      // If authenticated, navigate to the requested path
      await router.push(path);
      
    } catch (error) {
      console.error('Navigation error:', error);
      
      // If we get here, there was an error with navigation
      // Try a full page load as a last resort
      if (!isPublicPath) {
        window.location.href = path;
      }
    } finally {
      // Reset navigation state after a short delay
      setTimeout(() => {
        setIsNavigating(false);
      }, 100);
    }
  };

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 10);
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const handleLogin = (e?: React.MouseEvent) => {
    e?.preventDefault();
    if (isNavigating) return;
    handleNavigation('/login');
  };

  const handleRegister = (e?: React.MouseEvent) => {
    e?.preventDefault();
    if (isNavigating) return;
    handleNavigation('/register');
  };

  const toggleMenu = () => {
    if (isNavigating) return; // Prevent toggling during navigation
    setIsMenuOpen(!isMenuOpen);
  };

  return (
    <React.Fragment>
      {/* Desktop Header */}
      <header 
        className={`fixed w-full z-50 transition-all duration-300 ${isScrolled ? 'bg-white shadow-md' : 'bg-white'}`}
        style={{ height: '72px' }}
      >
        <div className="container mx-auto px-4 h-full">
          <div className="flex items-center justify-between h-full">
            {/* Left side - Logo and Menu */}
            <div className="flex items-center space-x-7">
              <div className="h-full">
                <div className="relative w-[150px] h-full">
                  <div className="relative w-full h-full">
                    <Image
                      src="/logo.png"
                      alt="London HSC"
                      className="mix-blend-multiply object-contain"
                      width={150}
                      height={140}
                      priority={true}
                      sizes="(max-width: 150px) 100vw, 150px"
                    />
                  </div>
                </div>
              </div>
              
              <nav className="hidden md:flex items-center space-x-2">
                <button 
                  className="px-3 py-1.5 border border-gray-300 rounded-lg bg-white text-blue-600 font-medium text-sm hover:bg-gray-50 flex items-center justify-center min-w-[80px]"
                  onClick={() => handleNavigation('/')}
                  disabled={isNavigating}
                >
                  {pathname === '/' && isNavigating ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Trang chủ'}
                </button>
                {(user || isAuthenticated()) && (
                  <>
                    <button 
                      className="px-3 py-1.5 border border-gray-300 rounded-lg bg-white text-blue-600 font-medium text-sm hover:bg-gray-50 flex items-center justify-center min-w-[120px]"
                      onClick={() => handleNavigation('/account/transactions')}
                      disabled={isNavigating}
                    >
                      {pathname === '/account/transactions' && isNavigating ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Lịch sử giao dịch'}
                    </button>
                    <button 
                      className="px-3 py-1.5 border border-gray-300 rounded-lg bg-white text-blue-600 font-medium text-sm hover:bg-gray-50 flex items-center justify-center min-w-[140px]"
                      onClick={() => handleNavigation('/account')}
                      disabled={isNavigating}
                    >
                      {pathname === '/account' && isNavigating ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Tổng quan tài khoản'}
                    </button>
                    <button 
                      className="px-3 py-1.5 border border-gray-300 rounded-lg bg-white text-blue-600 font-medium text-sm hover:bg-gray-50 flex items-center justify-center min-w-[140px]"
                      onClick={() => handleNavigation('/account/security')}
                      disabled={isNavigating}
                    >
                      {pathname === '/account/security' && isNavigating ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Thay đổi mật khẩu'}
                    </button>
                    <button 
                      className="px-3 py-1.5 border border-gray-300 rounded-lg bg-white text-blue-600 font-medium text-sm hover:bg-gray-50 flex items-center justify-center min-w-[140px]"
                      onClick={() => handleNavigation('/account/verify')}
                      disabled={isNavigating}
                    >
                      {pathname === '/account/verify' && isNavigating ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Xác minh danh tính'}
                    </button>
                    <button 
                      className="px-3 py-1.5 border border-gray-300 rounded-lg bg-white text-blue-600 font-medium text-sm hover:bg-gray-50 flex items-center justify-center min-w-[80px]"
                      onClick={() => handleNavigation('/deposit')}
                      disabled={isNavigating}
                    >
                      {pathname === '/deposit' && isNavigating ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Nạp tiền'}
                    </button>
                    <button 
                      className="px-3 py-1.5 border border-gray-300 rounded-lg bg-white text-blue-600 font-medium text-sm hover:bg-gray-50 flex items-center justify-center min-w-[80px]"
                      onClick={() => handleNavigation('/withdraw')}
                      disabled={isNavigating}
                    >
                      {pathname === '/withdraw' && isNavigating ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Rút tiền'}
                    </button>
                  </>
                )}
              </nav>
            </div>

            {/* Right side - Auth Buttons */}
            <div className="hidden md:flex items-center space-x-4">
              {!isLoading && !user && !isAuthenticated() ? (
                <>
                  <button 
                    className="bg-blue-600 text-white px-4 py-2 rounded-md font-medium hover:bg-blue-700 transition-colors text-sm"
                    onClick={handleLogin}
                  >
                    Đăng nhập
                  </button>
                  <div className="h-6 w-px bg-gray-300"></div>
                  <button 
                    className="bg-blue-600 text-white px-4 py-2 rounded-md font-medium hover:bg-blue-700 transition-colors text-sm"
                    onClick={handleRegister}
                  >
                    Mở tài khoản
                  </button>
                </>
              ) : (
                <div className="flex items-center space-x-4">
                  <a 
                    href={supportLink} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="text-blue-600 hover:text-blue-700 font-medium text-sm"
                  >
                    CSKH
                  </a>
                  <div className="relative group">
                    <button className="flex items-center space-x-1 text-sm font-medium text-gray-700 hover:text-blue-600">
                      <div className="w-8 h-8 rounded-full bg-blue-100 flex items-center justify-center">
                        <User className="w-4 h-4 text-blue-600" />
                      </div>
                      <div className="text-left">
                        <div className="font-medium">{user?.username || 'Tài khoản'}</div>
                        {balance !== null && (
                          <div className="text-xs text-gray-500 flex items-center">
                            {isRefreshing ? (
                              <Loader2 className="w-3 h-3 animate-spin mr-1" />
                            ) : (
                              <span>${balance.toLocaleString('vi-VN')}</span>
                            )}
                            <button 
                              onClick={(e) => {
                                e.stopPropagation();
                                setIsRefreshing(true);
                                fetchData();
                              }}
                              className="ml-1 text-blue-500 hover:text-blue-700"
                              disabled={isRefreshing}
                            >
                              <RefreshCw className={`w-3 h-3 ${isRefreshing ? 'animate-spin' : ''}`} />
                            </button>
                          </div>
                        )}
                      </div>
                      <ChevronDown className="w-4 h-4 ml-1" />
                    </button>
                    <div className="absolute right-0 mt-2 w-48 bg-white rounded-md shadow-lg py-1 z-50 hidden group-hover:block">
                      <button 
                        onClick={() => handleNavigation('/account')}
                        className="w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 flex items-center"
                      >
                        <User className="w-4 h-4 mr-2" /> Tài khoản của tôi
                      </button>
                      <button 
                        onClick={() => handleNavigation('/account/security')}
                        className="w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 flex items-center"
                      >
                        <Lock className="w-4 h-4 mr-2" /> Đổi mật khẩu
                      </button>
                      <button 
                        onClick={handleLogout}
                        className="w-full text-left px-4 py-2 text-sm text-red-600 hover:bg-gray-100 flex items-center"
                      >
                        <LogOut className="w-4 h-4 mr-2" /> Đăng xuất
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Mobile menu button */}
            <div className="md:hidden">
              <button 
                onClick={toggleMenu}
                className="text-blue-600 hover:text-blue-700 focus:outline-none"
                aria-label="Toggle menu"
              >
                <svg 
                  className="w-6 h-6" 
                  fill="none" 
                  stroke="currentColor" 
                  viewBox="0 0 24 24" 
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path 
                    strokeLinecap="round" 
                    strokeLinejoin="round" 
                    strokeWidth={2} 
                    d="M4 6h16M4 12h16M4 18h16" 
                  />
                </svg>
              </button>
            </div>
          </div>
        </div>

        {/* Mobile Menu */}
        {isMenuOpen && (
          <div className="md:hidden bg-white shadow-lg">
            <div className="container mx-auto px-4 py-2">
              <div className="flex flex-col space-y-1 py-2">
              {/* Always show home button */}
              <button 
                className="text-left py-3 px-3 text-blue-600 font-medium hover:bg-blue-50 rounded text-sm flex items-center"
                onClick={() => handleNavigation('/')}
              >
                {pathname === '/' && isNavigating ? (
                  <Loader2 className="w-4 h-4 animate-spin mr-2" />
                ) : null}
                <span>Trang chủ</span>
              </button>
              
              {/* Show these menu items only when user is logged in */}
              {(user || isAuthenticated()) ? (
                <>
                  <div className="border-t border-gray-100 my-1"></div>
                  
                  {/* Transactions */}
                  <button 
                    className="text-left py-3 px-3 text-blue-600 font-medium hover:bg-blue-50 rounded text-sm flex items-center"
                    onClick={() => handleNavigation('/account/transactions')}
                    disabled={isNavigating}
                  >
                    {pathname === '/account/transactions' && isNavigating ? (
                      <Loader2 className="w-4 h-4 animate-spin mr-2" />
                    ) : (
                      <History className="w-4 h-4 mr-2" />
                    )}
                    <span>Lịch sử giao dịch</span>
                  </button>
                  
                  {/* Account Overview */}
                  <button 
                    className="text-left py-3 px-3 text-blue-600 font-medium hover:bg-blue-50 rounded text-sm flex items-center"
                    onClick={() => handleNavigation('/account')}
                    disabled={isNavigating}
                  >
                    {pathname === '/account' && isNavigating ? (
                      <Loader2 className="w-4 h-4 animate-spin mr-2" />
                    ) : (
                      <User className="w-4 h-4 mr-2" />
                    )}
                    <span>Tổng quan tài khoản</span>
                  </button>
                  
                  {/* Change Password */}
                  <button 
                    className="text-left py-3 px-3 text-blue-600 font-medium hover:bg-blue-50 rounded text-sm flex items-center"
                    onClick={() => handleNavigation('/account/security')}
                    disabled={isNavigating}
                  >
                    {pathname === '/account/security' && isNavigating ? (
                      <Loader2 className="w-4 h-4 animate-spin mr-2" />
                    ) : (
                      <Lock className="w-4 h-4 mr-2" />
                    )}
                    <span>Thay đổi mật khẩu</span>
                  </button>
                  
                  {/* Identity Verification */}
                  <button 
                    className="text-left py-3 px-3 text-blue-600 font-medium hover:bg-blue-50 rounded text-sm flex items-center"
                    onClick={() => handleNavigation('/account/verify')}
                    disabled={isNavigating}
                  >
                    {pathname === '/account/verify' && isNavigating ? (
                      <Loader2 className="w-4 h-4 animate-spin mr-2" />
                    ) : (
                      <UserCheck className="w-4 h-4 mr-2" />
                    )}
                    <span>Xác minh danh tính</span>
                  </button>
                  
                  <div className="border-t border-gray-100 my-1"></div>
                  
                  {/* Deposit */}
                  <button 
                    className="text-left py-3 px-3 text-blue-600 font-medium hover:bg-blue-50 rounded text-sm flex items-center"
                    onClick={() => handleNavigation('/deposit')}
                    disabled={isNavigating}
                  >
                    {pathname === '/deposit' && isNavigating ? (
                      <Loader2 className="w-4 h-4 animate-spin mr-2" />
                    ) : (
                      <ArrowUpDown className="w-4 h-4 mr-2 transform rotate-90" />
                    )}
                    <span>Nạp tiền</span>
                  </button>
                  
                  {/* Withdraw */}
                  <button 
                    className="text-left py-3 px-3 text-blue-600 font-medium hover:bg-blue-50 rounded text-sm flex items-center"
                    onClick={() => handleNavigation('/withdraw')}
                    disabled={isNavigating}
                  >
                    {pathname === '/withdraw' && isNavigating ? (
                      <Loader2 className="w-4 h-4 animate-spin mr-2" />
                    ) : (
                      <ArrowUpDown className="w-4 h-4 mr-2 transform -rotate-90" />
                    )}
                    <span>Rút tiền</span>
                  </button>
                  
                  <div className="border-t border-gray-100 my-1"></div>
                  
                  {/* Customer Support */}
                  <a 
                    href={supportLink} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="text-left py-3 px-3 text-blue-600 font-medium hover:bg-blue-50 rounded text-sm flex items-center"
                  >
                    <span>CSKH (Telegram)</span>
                  </a>
                  
                  <div className="border-t border-gray-100 my-1"></div>
                  
                  {/* Logout */}
                  <button 
                    onClick={handleLogout}
                    className="text-left py-3 px-3 text-red-600 font-medium hover:bg-red-50 rounded text-sm flex items-center"
                    disabled={isNavigating}
                  >
                    <LogOut className="w-4 h-4 mr-2" />
                    <span>Đăng xuất</span>
                  </button>
                </>
              ) : (
                /* Show login/register buttons when not logged in */
                <>
                  <div className="border-t border-gray-100 my-1"></div>
                  <button 
                    className="w-full bg-blue-600 text-white py-3 px-4 rounded-md font-medium hover:bg-blue-700 mt-1 flex items-center justify-center"
                    onClick={handleLogin}
                    disabled={isNavigating}
                  >
                    {isNavigating ? (
                      <Loader2 className="w-4 h-4 animate-spin mr-2" />
                    ) : null}
                    <span>Đăng nhập</span>
                  </button>
                  <button 
                    className="w-full bg-blue-50 text-blue-600 py-3 px-4 rounded-md font-medium hover:bg-blue-100 flex items-center justify-center"
                    onClick={handleRegister}
                    disabled={isNavigating}
                  >
                    {isNavigating ? (
                      <Loader2 className="w-4 h-4 animate-spin mr-2" />
                    ) : null}
                    <span>Mở tài khoản</span>
                  </button>
                </>
              )}
            </div>
            </div>
          </div>
        )}
      </header>
    </React.Fragment>
  );
};

export default NewHeader;
