import { NextResponse } from 'next/server';
import { getMongoDb } from '@/lib/db';

export async function GET(request: Request) {
  try {
    const db = await getMongoDb();
    if (!db) {
      return NextResponse.json(
        { error: 'Không thể kết nối cơ sở dữ liệu' },
        { status: 500 }
      );
    }

    // Lấy 10 phiên gần đây nhất (bao gồm cả phiên hiện tại)
    const sessions = await db.collection('sessions')
      .find()
      .sort({ startTime: -1 })
      .limit(10)
      .toArray();

    return NextResponse.json(sessions);
  } catch (error) {
    console.error('Lỗi khi lấy danh sách phiên:', error);
    return NextResponse.json(
      { error: 'Đã xảy ra lỗi khi lấy danh sách phiên' },
      { status: 500 }
    );
  }
}
