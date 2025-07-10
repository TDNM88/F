"use client"

import type React from "react"

import { useEffect } from "react"
import { useRouter } from "next/navigation"
import { useAuth } from "@/lib/useAuth"

interface ProtectedRouteProps {
  children: React.ReactNode
  requiredRole?: "admin" | "user"
  redirectTo?: string
}

export function ProtectedRoute({ children, requiredRole = "user", redirectTo }: ProtectedRouteProps) {
  const { user, isLoading, isAuthenticated, isAdmin } = useAuth()
  const router = useRouter()

  useEffect(() => {
    if (!isLoading) {
      if (!isAuthenticated()) {
        // Not authenticated, redirect to login
        const loginUrl = redirectTo ? `/login?callbackUrl=${encodeURIComponent(redirectTo)}` : "/login"
        router.push(loginUrl)
        return
      }

      if (requiredRole === "admin" && !isAdmin()) {
        // User is not admin but trying to access admin route
        router.push("/")
        return
      }

      if (requiredRole === "user" && isAdmin()) {
        // Admin trying to access user route, redirect to admin
        router.push("/admin")
        return
      }
    }
  }, [isLoading, isAuthenticated, isAdmin, requiredRole, router, redirectTo])

  // Show loading spinner while checking auth
  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-white">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    )
  }

  // Don't render anything if not authenticated or wrong role
  if (!isAuthenticated() || (requiredRole === "admin" && !isAdmin()) || (requiredRole === "user" && isAdmin())) {
    return null
  }

  return <>{children}</>
}
