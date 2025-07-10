import { NextRequest, NextResponse } from 'next/server';
import { getMongoDb } from '@/lib/db';
import { ObjectId } from 'mongodb';
import { verifyToken } from '@/lib/auth';
import { uploadFile } from '@/lib/fileUpload';

// API để tạo yêu cầu nạp tiền mới
export async function POST(req: NextRequest) {
  try {
    // Xác thực người dùng
    const token = req.headers.get('authorization')?.split(' ')[1];
    if (!token) {
      return NextResponse.json({ message: 'Bạn cần đăng nhập' }, { status: 401 });
    }

    const tokenData = await verifyToken(token);
    if (!tokenData?.isValid) {
      return NextResponse.json({ message: 'Token không hợp lệ' }, { status: 401 });
    }
    
    // Lấy thông tin người dùng đầy đủ từ database
    const db = await getMongoDb();
    const user = await db.collection('users').findOne({ _id: new ObjectId(tokenData.userId) });
    if (!user) {
      return NextResponse.json({ message: 'Không tìm thấy người dùng' }, { status: 404 });
    }

    // Kiểm tra xem yêu cầu có chứa FormData không
    const formData = await req.formData();
    const amount = Number(formData.get('amount'));
    const bill = formData.get('bill') as File;

    if (!amount || !bill) {
      return NextResponse.json({ message: 'Thiếu thông tin cần thiết' }, { status: 400 });
    }



    // Lấy cài đặt hệ thống để kiểm tra giới hạn nạp tiền
    const settings = await db.collection('settings').findOne({});
    if (settings && amount < settings.depositLimits.min) {
      return NextResponse.json({ 
        message: `Số tiền nạp tối thiểu là ${settings.depositLimits.min.toLocaleString()} đ` 
      }, { status: 400 });
    }

    if (settings && amount > settings.depositLimits.max) {
      return NextResponse.json({ 
        message: `Số tiền nạp tối đa là ${settings.depositLimits.max.toLocaleString()} đ` 
      }, { status: 400 });
    }

    // Upload bill
    const proofImageUrl = await uploadFile(bill);

    // Generate unique deposit ID
    const timestamp = Date.now();
    const depositId = `NAP-${user.username || 'user'}-${timestamp}`;

    // Tạo yêu cầu nạp tiền mới
    const deposit = {
      depositId,
      user: new ObjectId(user._id),
      username: user.username || '',
      amount,
      status: 'CHO XU LY',
      proofImage: proofImageUrl,
      bankInfo: settings?.bankDetails[0] || {},
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const result = await db.collection('deposits').insertOne(deposit);

    // Gửi thông báo cho admin (có thể triển khai sau)
    // TODO: Gửi thông báo cho admin qua socket hoặc email

    return NextResponse.json({
      message: 'Yêu cầu nạp tiền đã được gửi',
      depositId: result.insertedId
    }, { status: 201 });

  } catch (error) {
    console.error('Error creating deposit request:', error);
    return NextResponse.json({ message: 'Đã xảy ra lỗi khi tạo yêu cầu nạp tiền' }, { status: 500 });
  }
}
