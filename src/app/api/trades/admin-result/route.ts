import { NextResponse } from 'next/server';
import { getMongoDb } from '@/lib/db';
import { verifyToken } from '@/lib/auth-utils';
import { NextRequest } from 'next/server';
import { parseSessionId } from '@/lib/sessionUtils';

export async function GET(request: NextRequest) {
  try {
    const user = await verifyToken(request);
    if (!user) {
      return NextResponse.json(
        { success: false, message: 'Chưa đăng nhập hoặc phiên đăng nhập đã hết hạn' },
        { status: 401 }
      );
    }

    const { searchParams } = new URL(request.url);
    const sessionId = searchParams.get('sessionId');

    if (!sessionId) {
      return NextResponse.json(
        { success: false, message: 'Thiếu thông tin phiên' },
        { status: 400 }
      );
    }

    const db = await getMongoDb();
    if (!db) {
      throw new Error('Không thể kết nối cơ sở dữ liệu');
    }

    // Tìm kết quả từ admin cho phiên này
    // Tìm cả sessionId chính xác và các sessionId cũ hơn trong cùng một phút
    const sessionStart = new Date(parseInt(sessionId.slice(0, 2)) + 2000, 
                                parseInt(sessionId.slice(2, 4)) - 1, 
                                parseInt(sessionId.slice(4, 6)), 
                                parseInt(sessionId.slice(6, 8)), 
                                parseInt(sessionId.slice(8, 10)));
    const sessionEnd = new Date(sessionStart.getTime() + 60000); // Thêm 1 phút

    const adminResult = await db.collection('admin_trades').findOne({
      $or: [
        { sessionId },
        {
          startTime: {
            $gte: sessionStart.toISOString(),
            $lt: sessionEnd.toISOString()
          },
          status: 'completed'
        }
      ]
    });

    // Kiểm tra quyền admin
    if (user.role !== 'admin') {
      return NextResponse.json(
        { success: false, message: 'Không có quyền truy cập' },
        { status: 403 }
      );
    }

    if (!adminResult) {
      return NextResponse.json(
        { success: false, message: 'Chưa có kết quả cho phiên này' },
        { status: 404 }
      );
    }

    return NextResponse.json({
      success: true,
      result: adminResult.result, // 'UP' hoặc 'DOWN'
      timestamp: adminResult.updatedAt
    });

  } catch (error) {
    console.error('Lỗi khi lấy kết quả từ admin:', error);
    return NextResponse.json(
      { success: false, message: 'Lỗi máy chủ nội bộ' },
      { status: 500 }
    );
  }
}
