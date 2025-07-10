import { NextResponse } from 'next/server';
import { withAuth } from '@/middleware/auth';
import type { AuthRequest } from '@/types/auth';

export const POST = withAuth(async (request: AuthRequest) => {
  try {
    const response = NextResponse.json({
      success: true,
      message: 'Đăng xuất thành công',
    });

    // Clear the token cookie
    response.cookies.set('token', '', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 0,
      path: '/',
      sameSite: 'lax',
    });

    return response;
  } catch (error) {
    console.error('Logout error:', error);
    return NextResponse.json(
      { success: false, message: 'Lỗi hệ thống' },
      { status: 500 }
    );
  }
});
