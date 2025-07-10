import { NextResponse } from 'next/server';
import { getToken } from 'next-auth/jwt';
import { getMongoDb } from '@/lib/db';
import { NextRequest } from 'next/server';
import { ObjectId } from 'mongodb';

interface User {
  _id: ObjectId;
  role?: string;
  [key: string]: any;
}

// Hàm lấy danh sách người dùng
export async function GET(request: NextRequest) {
  try {
    // Xác thực admin
    const token = await getToken({ 
      req: request as unknown as Request,
      secret: process.env.NEXTAUTH_SECRET
    });
    
    if (!token) {
      return NextResponse.json({ message: 'Chưa đăng nhập' }, { status: 401 });
    }
    
    const db = await getMongoDb();
    if (!db) {
      throw new Error('Could not connect to database');
    }
    
    const user = await db.collection('users').findOne<User>({ _id: new ObjectId(token.sub) });
    if (!user || user.role !== 'admin') {
      return NextResponse.json({ message: 'Không có quyền truy cập' }, { status: 403 });
    }

    // Lấy tham số tìm kiếm từ query string
    const { searchParams } = new URL(request.url);
    const search = searchParams.get('search') || '';
    const status = searchParams.get('status') || 'all';
    const page = parseInt(searchParams.get('page') || '1');
    const limit = parseInt(searchParams.get('limit') || '10');
    const startDate = searchParams.get('startDate');
    const endDate = searchParams.get('endDate');
    const skip = (page - 1) * limit;
    
    // Xây dựng query
    let query: any = {};
    
    // Tìm kiếm theo username hoặc fullName
    if (search) {
      query.$or = [
        { username: { $regex: search, $options: 'i' } },
        { fullName: { $regex: search, $options: 'i' } }
      ];
    }
    
    // Lọc theo trạng thái
    if (status !== 'all') {
      query['status.active'] = (status === 'active');
    }

    // Lọc theo ngày tạo
    if (startDate && endDate) {
      query.createdAt = {
        $gte: new Date(startDate),
        $lte: new Date(endDate)
      };
    }
    
    // Truy vấn database
    const total = await db.collection('users').countDocuments(query);
    
    const users = await db.collection('users')
      .find(query)
      .project({ password: 0 }) // Không trả về mật khẩu
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .toArray();

    return NextResponse.json({
      success: true,
      data: {
        users,
        pagination: {
          total,
          page,
          totalPages: Math.ceil(total / limit),
          limit
        }
      }
    });
  } catch (error) {
    console.error('Error fetching users:', error);
    return NextResponse.json(
      { success: false, message: 'Internal server error' },
      { status: 500 }
    );
  }
}

// API cập nhật trạng thái người dùng
export async function PUT(request: NextRequest) {
  try {
    const token = await getToken({ 
      req: request as unknown as Request,
      secret: process.env.NEXTAUTH_SECRET
    });
    
    if (!token) {
      return NextResponse.json({ message: 'Chưa đăng nhập' }, { status: 401 });
    }
    
    const db = await getMongoDb();
    if (!db) {
      throw new Error('Could not connect to database');
    }
    
    const user = await db.collection('users').findOne<User>({ _id: new ObjectId(token.sub) });
    if (!user || user.role !== 'admin') {
      return NextResponse.json({ message: 'Không có quyền truy cập' }, { status: 403 });
    }

    const { userId, status } = await request.json();
    
    if (!userId || typeof status !== 'boolean') {
      return NextResponse.json(
        { success: false, message: 'Thiếu thông tin bắt buộc' },
        { status: 400 }
      );
    }

    const result = await db.collection('users').updateOne(
      { _id: new ObjectId(userId) },
      { $set: { 'status.active': status } }
    );

    if (result.matchedCount === 0) {
      return NextResponse.json(
        { success: false, message: 'Không tìm thấy người dùng' },
        { status: 404 }
      );
    }

    return NextResponse.json({
      success: true,
      message: 'Cập nhật trạng thái thành công'
    });
  } catch (error) {
    console.error('Error updating user status:', error);
    return NextResponse.json(
      { success: false, message: 'Lỗi máy chủ nội bộ' },
      { status: 500 }
    );
  }
}

// API xóa người dùng
export async function DELETE(request: NextRequest) {
  try {
    const token = await getToken({ 
      req: request as unknown as Request,
      secret: process.env.NEXTAUTH_SECRET
    });
    
    if (!token) {
      return NextResponse.json({ message: 'Chưa đăng nhập' }, { status: 401 });
    }
    
    const db = await getMongoDb();
    if (!db) {
      throw new Error('Could not connect to database');
    }
    
    const user = await db.collection('users').findOne<User>({ _id: new ObjectId(token.sub) });
    if (!user || user.role !== 'admin') {
      return NextResponse.json({ message: 'Không có quyền truy cập' }, { status: 403 });
    }

    const { userId } = await request.json();
    
    if (!userId) {
      return NextResponse.json(
        { success: false, message: 'Thiếu ID người dùng' },
        { status: 400 }
      );
    }

    // Không cho xóa chính mình
    if (userId === token.sub) {
      return NextResponse.json(
        { success: false, message: 'Không thể xóa chính bạn' },
        { status: 400 }
      );
    }

    const result = await db.collection('users').deleteOne({ _id: new ObjectId(userId) });

    if (result.deletedCount === 0) {
      return NextResponse.json(
        { success: false, message: 'Không tìm thấy người dùng' },
        { status: 404 }
      );
    }

    return NextResponse.json({
      success: true,
      message: 'Xóa người dùng thành công'
    });
  } catch (error) {
    console.error('Error deleting user:', error);
    return NextResponse.json(
      { success: false, message: 'Lỗi máy chủ nội bộ' },
      { status: 500 }
    );
  }
}
