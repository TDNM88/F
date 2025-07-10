import { NextResponse } from 'next/server';
import { withAuth } from '@/middleware/auth';
import type { AuthRequest } from '@/types/auth';

// Using our new auth middleware
export const GET = withAuth(async (request: AuthRequest) => {
  try {
    // User is already authenticated by the middleware
    const user = request.user;
    
    // Prepare user response with default values
    const userResponse = {
      id: user._id,
      username: user.username || '',
      email: user.email || '',
      name: user.name || user.username || '',
      role: user.role || 'user',
      balance: user.balance || { available: 0, frozen: 0 },
      bank: user.bank || { 
        name: '', 
        accountNumber: '', 
        accountHolder: '' 
      },
      verification: user.verification || { 
        verified: false, 
        cccdFront: '', 
        cccdBack: '' 
      },
      status: user.status || { 
        active: true, 
        betLocked: false, 
        withdrawLocked: false 
      },
      createdAt: user.createdAt || new Date().toISOString(),
      updatedAt: user.updatedAt || new Date().toISOString(),
      lastLogin: user.lastLogin || new Date().toISOString()
    };

    return NextResponse.json({
      success: true,
      user: userResponse
    });
  } catch (error) {
    console.error('Error in /api/auth/me:', error);
    return NextResponse.json(
      { 
        success: false, 
        message: 'Lỗi hệ thống',
        _debug: process.env.NODE_ENV !== 'production' ? {
          error: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined
        } : undefined
      },
      { status: 500 }
    );
  }
});
