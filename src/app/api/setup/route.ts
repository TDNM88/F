import { NextResponse } from 'next/server';
import { getMongoDb } from '@/lib/db';
import { hashPassword } from '@/lib/auth';

// API endpoint tạm thời để tạo tài khoản admin
// Chỉ nên gọi API này một lần để tạo tài khoản admin ban đầu
// Sau khi sử dụng xong, nên xóa endpoint này hoặc thêm bảo vệ bổ sung

export async function GET(request: Request) {
  try {
    // Thông tin tài khoản admin cần tạo
    const adminUsername = 'admin';
    const adminPassword = 'admin123';
    
    // Kết nối đến MongoDB
    const db = await getMongoDb();
    if (!db) {
      return NextResponse.json({ message: 'Lỗi kết nối cơ sở dữ liệu' }, { status: 500 });
    }
    
    // Kiểm tra xem tài khoản admin đã tồn tại chưa
    const existingAdmin = await db.collection('users').findOne({ username: adminUsername });
    
    if (existingAdmin) {
      // Cập nhật tài khoản thành admin nếu đã tồn tại
      await db.collection('users').updateOne(
        { username: adminUsername },
        { $set: { role: 'admin' } }
      );
      
      return NextResponse.json({ 
        message: 'Tài khoản admin đã tồn tại. Đã cập nhật quyền admin.',
        userId: existingAdmin._id.toString()
      });
    } else {
      // Tạo mật khẩu đã băm
      const hashedPassword = await hashPassword(adminPassword);
      
      // Tạo tài khoản admin mới
      const newAdmin = {
        username: adminUsername,
        password: hashedPassword,
        fullName: 'Administrator',
        phone: '',
        role: 'admin',
        balance: { available: 0, frozen: 0 },
        createdAt: new Date(),
        updatedAt: new Date()
      };
      
      // Lưu vào cơ sở dữ liệu
      const result = await db.collection('users').insertOne(newAdmin);
      
      return NextResponse.json({
        message: 'Tạo tài khoản admin thành công',
        userId: result.insertedId.toString()
      }, { status: 201 });
    }
  } catch (error) {
    console.error('Lỗi khi tạo tài khoản admin:', error);
    return NextResponse.json({ 
      message: 'Lỗi khi tạo tài khoản admin', 
      error: (error as Error).message 
    }, { status: 500 });
  }
}
