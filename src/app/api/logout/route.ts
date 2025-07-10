import { NextResponse } from 'next/server';

export async function POST() {
  try {
    // Create a response with the success message
    const response = NextResponse.json({
      success: true,
      message: 'Đăng xuất thành công',
    });

    // Clear the authentication cookie by setting an expired date
    response.cookies.set('auth_token', '', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
      expires: new Date(0) // Set to past date to expire immediately
    });
    
    return response;
  } catch (error) {
    console.error('Logout error:', error);
    return NextResponse.json(
      { 
        success: false,
        message: 'Lỗi đăng xuất', 
        error: (error as Error).message 
      },
      { status: 500 }
    );
  }
}
