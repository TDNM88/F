import { NextResponse } from 'next/server';
import { getMongoDb } from '@/lib/db';
import { verifyToken } from '@/lib/auth-utils';
import { NextRequest } from 'next/server';
import { ObjectId } from 'mongodb';

export async function POST(request: NextRequest) {
  try {
    const user = await verifyToken(request);
    if (!user) {
      return NextResponse.json(
        { success: false, message: 'Chưa đăng nhập hoặc phiên đăng nhập đã hết hạn' },
        { status: 401 }
      );
    }

    const { tradeId, result, profit } = await request.json();

    if (!tradeId || !result) {
      return NextResponse.json(
        { success: false, message: 'Thiếu thông tin bắt buộc' },
        { status: 400 }
      );
    }

    const db = await getMongoDb();
    if (!db) {
      throw new Error('Không thể kết nối cơ sở dữ liệu');
    }

    // Cập nhật trạng thái giao dịch
    const updateResult = await db.collection('trades').updateOne(
      { _id: new ObjectId(tradeId), userId: new ObjectId(user._id) },
      { $set: { status: 'completed', result, profit, updatedAt: new Date() } }
    );

    // Cập nhật số dư người dùng nếu có lợi nhuận
    if (profit > 0) {
      await db.collection('users').updateOne(
        { _id: new ObjectId(user._id) },
        { $inc: { 'balance.available': profit } }
      );
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Lỗi khi cập nhật kết quả giao dịch:', error);
    return NextResponse.json(
      { success: false, message: 'Lỗi máy chủ nội bộ' },
      { status: 500 }
    );
  }
}
