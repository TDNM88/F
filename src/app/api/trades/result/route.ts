import { NextResponse } from 'next/server';
import { getMongoDb } from '@/lib/db';
import { getToken } from 'next-auth/jwt';
import { NextRequest } from 'next/server';

export async function POST(request: NextRequest) {
  try {
    const token = await getToken({ req: request });
    if (!token?.email) {
      return NextResponse.json(
        { success: false, message: 'Chưa đăng nhập' },
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
    await db.collection('trades').updateOne(
      { _id: tradeId },
      {
        $set: {
          status: 'completed',
          result,
          profit: profit || 0,
          completedAt: new Date(),
        },
      }
    );

    // Cập nhật số dư người dùng nếu có lợi nhuận
    if (profit && profit > 0) {
      await db.collection('users').updateOne(
        { email: token.email },
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
