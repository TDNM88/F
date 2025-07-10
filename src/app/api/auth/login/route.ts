import { NextResponse } from 'next/server';
import { comparePassword } from '@/lib/auth';
import { getMongoDb } from '@/lib/db';
import { generateToken } from '@/lib/auth';

export async function POST(request: Request) {
  try {
    const { username, password } = await request.json();

    if (!username || !password) {
      return NextResponse.json(
        { success: false, message: 'Tên đăng nhập và mật khẩu là bắt buộc' },
        { status: 400 }
      );
    }

    const db = await getMongoDb();
    const user = await db.collection('users').findOne({ username });

    if (!user) {
      return NextResponse.json(
        { success: false, message: 'Tên đăng nhập hoặc mật khẩu không đúng' },
        { status: 401 }
      );
    }

    const isPasswordValid = await comparePassword(password, user.password);
    if (!isPasswordValid) {
      return NextResponse.json(
        { success: false, message: 'Tên đăng nhập hoặc mật khẩu không đúng' },
        { status: 401 }
      );
    }

    // Generate token
    const token = generateToken(user._id.toString());
    
    // Prepare response
    const response = NextResponse.json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        username: user.username,
        role: user.role || 'user',
        balance: user.balance || 0
      }
    });

    // Set token in HTTP-only cookie với cấu hình phù hợp cho development
    // Trong development, httpOnly:false giúp client script đọc cookie để debug
    console.debug('Setting auth cookie token:', { tokenLength: token.length });
    
    response.cookies.set('token', token, {
      httpOnly: process.env.NODE_ENV === 'production', // Tắt httpOnly trong development để debug
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60, // 7 days in seconds
      path: '/',
      sameSite: 'lax',
    });
    
    // Thêm debug cookie không httpOnly để client có thể kiểm tra
    if (process.env.NODE_ENV !== 'production') {
      response.cookies.set('debug_token', 'exists', {
        httpOnly: false,
        secure: false,
        maxAge: 7 * 24 * 60 * 60,
        path: '/',
      });
    }

    return response;
  } catch (error) {
    console.error('Login error:', error);
    return NextResponse.json(
      { success: false, message: 'Lỗi hệ thống' },
      { status: 500 }
    );
  }
}
