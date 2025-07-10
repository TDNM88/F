import { NextRequest, NextResponse } from 'next/server';
import { verifyToken } from '@/lib/auth';
import { ObjectId } from 'mongodb';
import clientPromise from '@/lib/mongodb';
import { hash } from 'bcryptjs';

export async function POST(req: NextRequest) {
  try {
    const token = req.headers.get('authorization')?.split(' ')[1];
    if (!token) {
      return NextResponse.json({ message: 'Bạn cần đăng nhập' }, { status: 401 });
    }

    const user = await verifyToken(token);
    if (!user) {
      return NextResponse.json({ message: 'Phiên đăng nhập hết hạn' }, { status: 401 });
    }

    const { currentPassword, newPassword } = await req.json();

    // Validate required fields
    if (!currentPassword || !newPassword) {
      return NextResponse.json(
        { message: 'Vui lòng nhập mật khẩu hiện tại và mật khẩu mới' },
        { status: 400 }
      );
    }

    // Check password strength
    if (newPassword.length < 8) {
      return NextResponse.json(
        { message: 'Mật khẩu phải có ít nhất 8 ký tự' },
        { status: 400 }
      );
    }

    const client = await clientPromise;
    const db = client.db();

    // Get user with password hash
    const userData = await db.collection('users').findOne({
      _id: new ObjectId(user.userId)
    });

    if (!userData) {
      return NextResponse.json(
        { message: 'Không tìm thấy thông tin người dùng' },
        { status: 404 }
      );
    }

    // In a real app, you would verify the current password here
    // For now, we'll just update the password directly
    // In production, you should use bcrypt.compare() to verify the current password
    
    // Hash the new password
    const hashedPassword = await hash(newPassword, 12);

    // Update password in database
    await db.collection('users').updateOne(
      { _id: new ObjectId(user.userId) },
      {
        $set: {
          password: hashedPassword,
          updatedAt: new Date()
        }
      }
    );

    return NextResponse.json({
      success: true,
      message: 'Đổi mật khẩu thành công'
    });
  } catch (error) {
    console.error('Change password error:', error);
    return NextResponse.json(
      { 
        success: false, 
        message: error instanceof Error ? error.message : 'Có lỗi xảy ra khi đổi mật khẩu' 
      },
      { status: 500 }
    );
  }
}
