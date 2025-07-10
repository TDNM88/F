"use client"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "./ui/dropdown-menu"
import { User, LogOut } from "lucide-react"

interface UserMenuProps {
  user: { username: string; role: string } | null
  logout: () => void
}

export default function UserMenu({ user, logout }: UserMenuProps) {
  if (!user) {
    return (
      <Button variant="ghost" className="text-white" disabled>
        <User className="h-5 w-5 mr-2" />
        Loading...
      </Button>
    );
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" className="text-white">
          <User className="h-5 w-5 mr-2" />
          {user?.username || 'User'}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent className="bg-gray-800 border-gray-700 text-white">
        <DropdownMenuLabel>{user?.role === "admin" ? "Quản trị" : "Khách hàng"}</DropdownMenuLabel>
        <DropdownMenuSeparator className="bg-gray-700" />
        <DropdownMenuItem onClick={logout} className="text-red-500 hover:bg-gray-700">
          <LogOut className="h-4 w-4 mr-2" />
          Đăng xuất
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
