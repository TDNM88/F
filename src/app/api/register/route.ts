import { NextResponse } from 'next/server';
import { getMongoDb } from '@/lib/db';
import { hashPassword, generateToken } from '@/lib/auth';

export async function POST(request: Request) {
  try {
    const { username, password, email, name } = await request.json();

    // Validate input
    if (!username || !password || !email) {
      return NextResponse.json(
        { success: false, message: 'Vui lòng nhập đầy đủ thông tin' },
        { status: 400 }
      );
    }

    // Validate username format
    if (username.length < 3) {
      return NextResponse.json(
        { success: false, message: 'Tên đăng nhập phải có ít nhất 3 ký tự' },
        { status: 400 }
      );
    }

    // Validate password length
    if (password.length < 6) {
      return NextResponse.json(
        { success: false, message: 'Mật khẩu phải có ít nhất 6 ký tự' },
        { status: 400 }
      );
    }

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return NextResponse.json(
        { success: false, message: 'Email không hợp lệ' },
        { status: 400 }
      );
    }

    const db = await getMongoDb();
    if (!db) {
      throw new Error('Không thể kết nối cơ sở dữ liệu');
    }

    // Check if username or email already exists
    const existingUser = await db.collection('users').findOne({
      $or: [
        { username: username.trim().toLowerCase() },
        { email: email.trim().toLowerCase() }
      ]
    });

    if (existingUser) {
      if (existingUser.username === username.trim().toLowerCase()) {
        return NextResponse.json(
          { success: false, message: 'Tên đăng nhập đã được sử dụng' },
          { status: 400 }
        );
      } else {
        return NextResponse.json(
          { success: false, message: 'Email đã được đăng ký' },
          { status: 400 }
        );
      }
    }

    // Hash password
    const hashedPassword = await hashPassword(password);
    const now = new Date();

    // Create new user
    const newUser = {
      username: username.trim().toLowerCase(),
      email: email.trim().toLowerCase(),
      name: name?.trim() || username.trim(),
      password: hashedPassword,
      role: 'user',
      balance: {
        available: 0,
        frozen: 0,
      },
      bank: {
        name: '',
        accountNumber: '',
        accountHolder: '',
      },
      verification: {
        verified: false,
        cccdFront: '',
        cccdBack: '',
      },
      status: {
        active: true,
        betLocked: false,
        withdrawLocked: false,
      },
      lastLogin: now,
      createdAt: now,
      updatedAt: now,
    };

    const result = await db.collection('users').insertOne(newUser);

    if (!result.insertedId) {
      throw new Error('Không thể tạo tài khoản');
    }

    // Generate token for auto-login after registration
    const token = generateToken(result.insertedId.toString());

    // Prepare response with user data (excluding password)
    const { password: _, ...userWithoutPassword } = newUser;
    const responseData = {
      success: true,
      message: 'Đăng ký thành công!',
      user: {
        ...userWithoutPassword,
        _id: result.insertedId.toString(),
      },
    };

    const response = NextResponse.json(responseData);

    // Set token in HTTP-only cookie
    response.cookies.set('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60, // 7 days
      path: '/',
      sameSite: 'lax',
    });

    return response;
  } catch (error) {
    console.error('Lỗi đăng ký:', error);
    return NextResponse.json(
      { 
        success: false, 
        message: error instanceof Error ? error.message : 'Lỗi hệ thống' 
      },
      { status: 500 }
    );
  }
}
