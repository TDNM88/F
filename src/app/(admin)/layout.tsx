import type React from "react"
import type { Metadata } from "next"
import { Inter } from "next/font/google"
import { cn } from "@/lib/utils"
import { ProtectedRoute } from "@/components/auth/protected-route"

const inter = Inter({ subsets: ["latin"] })

export const metadata: Metadata = {
  title: "Admin Dashboard",
  description: "Quản trị viên",
}

export default function AdminLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="vi" suppressHydrationWarning>
      <body className="min-h-screen bg-background font-sans antialiased">
        <ProtectedRoute requiredRole="admin">
          {children}
        </ProtectedRoute>
      </body>
    </html>
  )
}
