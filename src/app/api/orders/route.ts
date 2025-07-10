import { NextResponse } from 'next/server';
import { getMongoDb } from '@/lib/db';
import { verifyToken } from '@/lib/auth';
import { MongoClient, ObjectId } from 'mongodb';

interface UserData {
  _id: ObjectId;
  balance: number;
  // Thêm các trường khác nếu cần
}

interface DecodedToken {
  userId: string;
  // Thêm các trường khác nếu cần
}

export async function POST(request: Request) {
  let client: MongoClient | null = null;
  
  try {
    const authHeader = request.headers.get('authorization');
    if (!authHeader) {
      return NextResponse.json(
        { error: 'Không tìm thấy token xác thực' },
        { status: 401 }
      );
    }

    const token = authHeader.split(' ')[1];
    const decodedToken = verifyToken(token);
    
    if (!decodedToken || typeof decodedToken !== 'object' || !('userId' in decodedToken)) {
      return NextResponse.json(
        { error: 'Token không hợp lệ hoặc đã hết hạn' },
        { status: 401 }
      );
    }
    
    const decoded = decodedToken as DecodedToken;

    const { sessionId, direction, amount, asset } = await request.json();
    
    if (!sessionId || !direction || !amount || !asset) {
      return NextResponse.json(
        { error: 'Thiếu thông tin bắt buộc' },
        { status: 400 }
      );
    }

    // Lấy kết nối MongoDB
    const mongoDb = await getMongoDb();
    if (!mongoDb) {
      return NextResponse.json(
        { error: 'Không thể kết nối cơ sở dữ liệu' },
        { status: 500 }
      );
    }

    // Ép kiểu để lấy client
    client = (mongoDb as any).client as MongoClient;
    
    // Tạo ObjectId từ userId
    let userId: ObjectId;
    try {
      const userIdStr = String(decodedToken.userId);
      userId = new ObjectId(userIdStr);
    } catch (error) {
      return NextResponse.json(
        { error: 'Định dạng ID người dùng không hợp lệ' },
        { status: 400 }
      );
    }

    // Kiểm tra số dư tài khoản
    const user = await mongoDb.collection<UserData>('users').findOne({ _id: userId });
    if (!user) {
      return NextResponse.json(
        { error: 'Không tìm thấy thông tin người dùng' },
        { status: 404 }
      );
    }

    // Kiểm tra số dư
    if (user.balance < amount) {
      return NextResponse.json(
        { error: 'Số dư không đủ để thực hiện giao dịch' },
        { status: 400 }
      );
    }

    // Tạo đơn hàng mới
    const order = {
      userId: userId,
      sessionId,
      direction,
      amount: Number(amount),
      asset,
      status: 'pending',
      createdAt: new Date(),
      updatedAt: new Date()
    };

    // Bắt đầu session
    const session = client.startSession();
    
    try {
      await session.withTransaction(async () => {
        // Trừ số dư tài khoản
        await mongoDb.collection('users').updateOne(
          { _id: userId },
          { $inc: { balance: -Number(amount) } },
          { session }
        );

        // Lưu đơn hàng
        await mongoDb.collection('orders').insertOne(order, { session });
      });

      return NextResponse.json({
        success: true,
        message: 'Đặt lệnh thành công'
      });

    } catch (error) {
      console.error('Lỗi trong transaction:', error);
      throw error;
    } finally {
      await session.endSession();
    }

  } catch (error: any) {
    console.error('Lỗi khi đặt lệnh:', error);
    return NextResponse.json(
      { error: error.message || 'Đã xảy ra lỗi khi đặt lệnh' },
      { status: 500 }
    );
  } finally {
    // Đảm bảo đóng kết nối
    if (client) {
      await client.close();
    }
  }
}
