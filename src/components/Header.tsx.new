"use client"

import { useRouter, usePathname } from "next/navigation"
import Image from "next/image"
import Link from "next/link"
import { useState, useEffect } from "react"
import { useAuth } from "@/lib/useAuth"
import { Button } from "./ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "./ui/dropdown-menu"
import { User as UserIcon, LogOut, Wallet, CreditCard, ArrowUpRight, ArrowDownLeft, 
  Clock, ChevronDown, Phone, Menu, X } from "lucide-react"

export default function Header() {
  const router = useRouter()
  const { user, loading, logout } = useAuth()
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false)
  const [scrolled, setScrolled] = useState(false)

  // Handle scrolling effect
  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 10)
    }
    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  const handleLogout = async () => {
    try {
      await logout()
      router.push("/")
    } catch (error) {
      console.error("Logout error:", error)
    }
  }
  
  // Track pathname for route changes
  const pathname = usePathname()
  
  // Close mobile menu when route changes
  useEffect(() => {
    setIsMobileMenuOpen(false)
  }, [pathname])

  return (
    <header className={`bg-white border-b border-gray-100 sticky top-0 z-50 ${scrolled ? 'shadow-md' : 'shadow-sm'}`}>
      <div className="container mx-auto px-4 h-16 flex items-center justify-between">
        {/* Left side: Logo and Navigation */}
        <div className="flex items-center">
          {/* Logo */}
          <Link href="/" className="flex items-center mr-4">
            <Image 
              src="/logo.png" 
              alt="London HSC" 
              width={120} 
              height={40} 
              className="h-10 w-auto"
              priority
            />
          </Link>
          
          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-2">
            <Button
              variant="outline"
              size="sm"
              className="text-blue-600 border-blue-600 bg-white hover:bg-blue-50"
              onClick={() => router.push("/")}
            >
              Trang chủ
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="text-blue-600 border-blue-600 bg-white hover:bg-blue-50"
              onClick={() => router.push("/trade")}
            >
              Giao dịch
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="text-blue-600 border-blue-600 bg-white hover:bg-blue-50"
              onClick={() => router.push("/")}
            >
              Tin tức
            </Button>
            
            {/* Wallet dropdown for logged in users */}
            {!loading && user && (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" size="sm" className="text-blue-600 border-blue-600 bg-white hover:bg-blue-50">
                    <span>Ví</span>
                    <ChevronDown className="h-4 w-4 ml-1" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="start" className="w-56">
                  <DropdownMenuItem onClick={() => router.push("/deposit")}>
                    <ArrowDownLeft className="mr-2 h-4 w-4" />
                    <span>Nạp tiền</span>
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => router.push("/withdraw")}>
                    <ArrowUpRight className="mr-2 h-4 w-4" />
                    <span>Rút tiền</span>
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => router.push("/orders")}>
                    <Clock className="mr-2 h-4 w-4" />
                    <span>Lịch sử giao dịch</span>
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            )}
          </div>
        </div>
        
        {/* Right side */}
        <div className="flex items-center gap-3">
          {/* CSKH button - hidden on mobile */}
          <Button 
            variant="ghost" 
            size="sm" 
            className="hidden sm:flex text-blue-600 hover:bg-blue-50"
            onClick={() => router.push("/support")}
          >
            CSKH
          </Button>
          
          {/* Mobile menu button */}
          <Button 
            variant="ghost" 
            size="icon" 
            className="md:hidden" 
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
          >
            {isMobileMenuOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </Button>
          
          {/* User Account dropdown */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              {user ? (
                <Button variant="ghost" size="icon" className="rounded-full overflow-hidden h-8 w-8">
                  <Image 
                    src={user.avatar || "/avatars/default.png"} 
                    alt={user.username || "User"} 
                    width={32} 
                    height={32} 
                    className="h-full w-full object-cover"
                  />
                </Button>
              ) : (
                <Button variant="outline" size="sm" className="gap-2">
                  <UserIcon className="h-4 w-4" />
                  <span>Tài khoản</span>
                  <ChevronDown className="h-4 w-4" />
                </Button>
              )}
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56">
              {user ? (
                <>
                  {/* Username display */}
                  <div className="px-4 py-2 text-sm font-medium">{user.username || 'tdnm'}</div>
                  
                  <DropdownMenuItem onClick={() => router.push("/account")}>
                    <span>Tổng quan tài khoản</span>
                  </DropdownMenuItem>
                  
                  <DropdownMenuItem onClick={() => router.push("/security")}>
                    <span>Cài đặt bảo mật</span>
                  </DropdownMenuItem>
                  
                  <DropdownMenuItem onClick={() => router.push("/verification")}>
                    <span>Xác minh danh tính</span>
                  </DropdownMenuItem>
                  
                  <DropdownMenuSeparator />
                  
                  <DropdownMenuItem onClick={handleLogout}>
                    <span>Đăng xuất</span>
                  </DropdownMenuItem>
                </>
              ) : (
                <>
                  <DropdownMenuItem onClick={() => router.push("/login")}>
                    <span>Đăng nhập</span>
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => router.push("/register")}>
                    <span>Mở tài khoản</span>
                  </DropdownMenuItem>
                </>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
      
      {/* Mobile Menu Overlay */}
      {isMobileMenuOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 z-40" onClick={() => setIsMobileMenuOpen(false)}></div>
      )}
      
      {/* Mobile Menu Drawer */}
      <div className={`fixed top-16 left-0 w-full bg-white z-40 transform transition-transform duration-300 ease-in-out shadow-lg ${isMobileMenuOpen ? 'translate-y-0' : '-translate-y-full'}`}>
        <div className="border-t border-gray-200">
          <nav className="flex flex-col w-full">
            <Link href="/" className="py-3 px-4 border-b border-gray-200 hover:bg-gray-50">
              Trang chủ
            </Link>
            <Link href="/trade" className="py-3 px-4 border-b border-gray-200 hover:bg-gray-50">
              Giao dịch
            </Link>
            <Link href="/orders" className="py-3 px-4 border-b border-gray-200 hover:bg-gray-50">
              Lịch sử giao dịch
            </Link>
            <Link href="/account" className="py-3 px-4 border-b border-gray-200 hover:bg-gray-50">
              Tổng quan tài khoản
            </Link>
            <Link href="/security" className="py-3 px-4 border-b border-gray-200 hover:bg-gray-50">
              Cài đặt bảo mật
            </Link>
            <Link href="/verification" className="py-3 px-4 border-b border-gray-200 hover:bg-gray-50">
              Xác minh danh tính
            </Link>
            <div className="grid grid-cols-2 gap-4 p-4">
              <Link href="/deposit" className="bg-green-600 text-white py-3 rounded-md flex justify-center items-center font-medium">
                Nạp tiền
              </Link>
              <Link href="/withdraw" className="bg-green-600 text-white py-3 rounded-md flex justify-center items-center font-medium">
                Rút tiền
              </Link>
            </div>
            <button 
              onClick={handleLogout}
              className="mx-4 mb-4 bg-white border border-gray-300 text-gray-700 py-3 rounded-md flex justify-center items-center font-medium"
            >
              Đăng xuất
            </button>
          </nav>
        </div>
      </div>
    </header>
  );
}
