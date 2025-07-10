"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { useAuth } from "@/lib/useAuth"
import { Button } from "@/components/ui/button"
import { LogOut, Home, Users, Clock, ArrowDownToLine, ArrowUpFromLine, Settings, LineChart } from "lucide-react"

const AdminSidebar = () => {
  const pathname = usePathname()
  const { user, logout } = useAuth()

  if (!user) return null

  // Check if the current path is active
  const isActive = (path: string) => {
    return pathname === path || pathname.startsWith(`${path}/`)
  }

  // Menu items for admin
  const menuItems = [
    {
      href: "/admin",
      icon: <Home className="h-4 w-4" />,
      label: "Tổng quan",
    },
    {
      href: "/admin/sessions",
      icon: <Clock className="h-4 w-4" />,
      label: "Quản lý phiên",
    },
    {
      href: "/admin/users",
      icon: <Users className="h-4 w-4" />,
      label: "Quản lý người dùng",
    },
    {
      href: "/admin/deposits",
      icon: <ArrowDownToLine className="h-4 w-4" />,
      label: "Quản lý nạp tiền",
    },
    {
      href: "/admin/withdrawals",
      icon: <ArrowUpFromLine className="h-4 w-4" />,
      label: "Quản lý rút tiền",
    },
    {
      href: "/admin/orders",
      icon: <LineChart className="h-4 w-4" />,
      label: "Lịch sử giao dịch",
    },
    {
      href: "/admin/settings",
      icon: <Settings className="h-4 w-4" />,
      label: "Cài đặt hệ thống",
    },
  ]

  return (
    <div className="bg-white shadow rounded-lg p-4">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="font-bold text-lg">Quản trị viên</h2>
          <p className="text-sm text-gray-500">{user.username}</p>
        </div>
        <Button variant="outline" size="sm" onClick={logout} className="flex items-center gap-1 bg-transparent">
          <LogOut className="h-4 w-4" />
          Đăng xuất
        </Button>
      </div>

      <div className="space-y-1">
        {menuItems.map((item) => (
          <Link key={item.href} href={item.href}>
            <Button variant={isActive(item.href) ? "secondary" : "ghost"} className="w-full justify-start">
              <span className="mr-2">{item.icon}</span>
              {item.label}
            </Button>
          </Link>
        ))}
      </div>

      <div className="mt-6 pt-4 border-t">
        <Link href="/trade">
          <Button variant="outline" className="w-full justify-start bg-transparent">
            <Home className="h-4 w-4 mr-2" />
            Về trang người dùng
          </Button>
        </Link>
      </div>
    </div>
  )
}

export default AdminSidebar
