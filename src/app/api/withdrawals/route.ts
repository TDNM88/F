import { NextRequest, NextResponse } from 'next/server';
import { getMongoDb } from '@/lib/db';
import { ObjectId } from 'mongodb';
import { verifyToken } from '@/lib/auth';

// API để tạo yêu cầu rút tiền mới
export async function POST(req: NextRequest) {
  try {
    // Xác thực người dùng
    const token = req.headers.get('authorization')?.split(' ')[1];
    if (!token) {
      return NextResponse.json({ message: 'Bạn cần đăng nhập' }, { status: 401 });
    }

    const userFromToken = await verifyToken(token);
    if (!userFromToken || !userFromToken.id) {
      return NextResponse.json({ message: 'Token không hợp lệ' }, { status: 401 });
    }

    // Parse request body
    const { amount, bankName, accountNumber, accountHolder } = await req.json();

    if (!amount || !bankName || !accountNumber || !accountHolder) {
      return NextResponse.json({ message: 'Thiếu thông tin cần thiết' }, { status: 400 });
    }

    // Kết nối DB
    const db = await getMongoDb();

    // Lấy thông tin người dùng
    const user = await db.collection('users').findOne({ _id: new ObjectId(userFromToken.id) });
    if (!user) {
      return NextResponse.json({ message: 'Không tìm thấy người dùng' }, { status: 404 });
    }

    // Lấy cài đặt hệ thống để kiểm tra giới hạn rút tiền
    const settings = await db.collection('settings').findOne({});
    if (settings && amount < settings.withdrawalLimits.min) {
      return NextResponse.json({ 
        message: `Số tiền rút tối thiểu là ${settings.withdrawalLimits.min.toLocaleString()} đ` 
      }, { status: 400 });
    }

    if (settings && amount > settings.withdrawalLimits.max) {
      return NextResponse.json({ 
        message: `Số tiền rút tối đa là ${settings.withdrawalLimits.max.toLocaleString()} đ` 
      }, { status: 400 });
    }

    // Kiểm tra số dư
    if (user.balance < amount) {
      return NextResponse.json({ message: 'Số dư không đủ' }, { status: 400 });
    }

    // Tạo yêu cầu rút tiền mới với ID theo định dạng RUT-username-timestamp
    const timestamp = new Date().getTime();
    const username = userFromToken.username || 'user';
    const withdrawalId = `RUT-${username}-${timestamp}`;

    const withdrawal = {
      _id: withdrawalId,
      user: new ObjectId(userFromToken.id),
      username: user.username,
      amount,
      bankName,
      bankAccountNumber: accountNumber,
      accountHolder: accountHolder,
      status: 'Chờ duyệt',
      notes: '',
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const result = await db.collection('withdrawals').insertOne(withdrawal);

    // Tạm thời giảm số dư người dùng (sẽ hoàn lại nếu yêu cầu bị từ chối)
    await db.collection('users').updateOne(
      { _id: new ObjectId(userFromToken.id) },
      { $inc: { balance: -amount } }
    );

    // Gửi thông báo cho admin (có thể triển khai sau)
    // TODO: Gửi thông báo cho admin qua socket hoặc email

    return NextResponse.json({
      message: 'Yêu cầu rút tiền đã được gửi',
      withdrawalId: result.insertedId
    }, { status: 201 });

  } catch (error) {
    console.error('Error creating withdrawal request:', error);
    return NextResponse.json({ message: 'Đã xảy ra lỗi khi tạo yêu cầu rút tiền' }, { status: 500 });
  }
}
