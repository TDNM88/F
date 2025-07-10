import { NextResponse } from 'next/server';
import { withAuth } from '@/middleware/auth';
import type { AuthRequest } from '@/types/auth';

// This endpoint verifies the authentication status of the current user
export const GET = withAuth(async (request: AuthRequest) => {
  try {
    // If we get here, the user is authenticated
    const { user } = request;
    
    // Return user info without password
    return NextResponse.json({
      valid: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        name: user.name,
        role: user.role,
        balance: user.balance || { available: 0, frozen: 0 },
        bank: user.bank || { name: '', accountNumber: '', accountHolder: '' },
        verification: user.verification || { 
          verified: false, 
          cccdFront: '',
          cccdBack: ''
        },
        status: {
          active: user.status?.active ?? true,
          betLocked: user.status?.betLocked ?? false,
          withdrawLocked: user.status?.withdrawLocked ?? false,
        },
        lastLogin: user.lastLogin || null,
      },
    });
  } catch (error) {
    console.error('Verify error:', error);
    return NextResponse.json(
      { valid: false, message: 'Internal server error' },
      { status: 500 }
    );
  }
});
