import { NextRequest, NextResponse } from 'next/server';
import { getMongoDb } from '@/lib/db';
import { ObjectId } from 'mongodb';
import { verifyToken } from '@/lib/auth';

// API để lấy danh sách yêu cầu rút tiền (dành cho Admin)
export async function GET(req: NextRequest) {
  try {
    // Xác thực admin
    const token = req.headers.get('authorization')?.split(' ')[1];
    if (!token) {
      return NextResponse.json({ message: 'Bạn cần đăng nhập' }, { status: 401 });
    }

    const user = await verifyToken(token);
    if (!user || !user.id) {
      return NextResponse.json({ message: 'Token không hợp lệ' }, { status: 401 });
    }

    // Kết nối DB
    const db = await getMongoDb();

    // Kiểm tra quyền admin
    if (user.role !== 'admin') {
      return NextResponse.json({ message: 'Bạn không có quyền truy cập' }, { status: 403 });
    }

    // Parse query params
    const url = new URL(req.url);
    const page = parseInt(url.searchParams.get('page') || '1');
    const limit = parseInt(url.searchParams.get('limit') || '10');
    const status = url.searchParams.get('status');
    const skip = (page - 1) * limit;

    // Tạo filter
    const filter: any = {};
    if (status) {
      filter.status = status;
    }

    // Pipeline aggregation để lấy thông tin người dùng
    const pipeline = [
      { $match: filter },
      {
        $lookup: {
          from: 'users',
          localField: 'user',
          foreignField: '_id',
          as: 'userDetails'
        }
      },
      { $unwind: '$userDetails' },
      { $sort: { createdAt: -1 } },
      { $skip: skip },
      { $limit: limit },
      {
        $project: {
          _id: 1,
          amount: 1,
          bank: 1,
          status: 1,
          notes: 1,
          createdAt: 1,
          updatedAt: 1,
          'userDetails._id': 1,
          'userDetails.username': 1,
          'userDetails.fullName': 1,
          'userDetails.phone': 1
        }
      }
    ];

    const withdrawals = await db.collection('withdrawals').aggregate(pipeline).toArray();

    // Lấy tổng số bản ghi để phân trang
    const total = await db.collection('withdrawals').countDocuments(filter);

    return NextResponse.json({
      withdrawals,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit)
    });

  } catch (error) {
    console.error('Error fetching withdrawal requests:', error);
    return NextResponse.json({ message: 'Đã xảy ra lỗi khi lấy danh sách yêu cầu rút tiền' }, { status: 500 });
  }
}

// API để xử lý yêu cầu rút tiền (phê duyệt, đang xử lý, hoàn thành, từ chối)
export async function PUT(req: NextRequest) {
  try {
    // Xác thực admin
    const token = req.headers.get('authorization')?.split(' ')[1];
    if (!token) {
      return NextResponse.json({ message: 'Bạn cần đăng nhập' }, { status: 401 });
    }

    const user = await verifyToken(token);
    if (!user || !user.id) {
      return NextResponse.json({ message: 'Token không hợp lệ' }, { status: 401 });
    }

    // Parse request body
    const { withdrawalId, status, notes } = await req.json();

    if (!withdrawalId || !status) {
      return NextResponse.json({ message: 'Thiếu thông tin cần thiết' }, { status: 400 });
    }

    if (!['processing', 'completed', 'rejected'].includes(status)) {
      return NextResponse.json({ message: 'Trạng thái không hợp lệ' }, { status: 400 });
    }

    // Kết nối DB
    const db = await getMongoDb();

    // Kiểm tra quyền admin
    if (user.role !== 'admin') {
      return NextResponse.json({ message: 'Bạn không có quyền truy cập' }, { status: 403 });
    }

    // Lấy thông tin yêu cầu rút tiền
    const withdrawal = await db.collection('withdrawals').findOne({ _id: new ObjectId(withdrawalId) });
    if (!withdrawal) {
      return NextResponse.json({ message: 'Không tìm thấy yêu cầu rút tiền' }, { status: 404 });
    }

    // Nếu yêu cầu đã được hoàn thành hoặc từ chối
    if (withdrawal.status === 'completed' || withdrawal.status === 'rejected') {
      return NextResponse.json({ message: 'Yêu cầu này đã được xử lý hoàn tất' }, { status: 400 });
    }

    // Cập nhật trạng thái yêu cầu
    await db.collection('withdrawals').updateOne(
      { _id: new ObjectId(withdrawalId) },
      {
        $set: {
          status,
          notes: notes || withdrawal.notes || '',
          processedBy: new ObjectId(user.id),
          processedAt: new Date(),
          updatedAt: new Date()
        }
      }
    );

    // Nếu từ chối, hoàn lại tiền cho người dùng
    if (status === 'rejected') {
      await db.collection('users').updateOne(
        { _id: withdrawal.user },
        { $inc: { balance: withdrawal.amount } }
      );
    }

    // Tạo thông báo cho người dùng
    const notificationMessage = 
      status === 'processing' ? 'Yêu cầu rút tiền của bạn đang được xử lý' :
      status === 'completed' ? 'Yêu cầu rút tiền của bạn đã được hoàn thành' :
      'Yêu cầu rút tiền của bạn đã bị từ chối';

    await db.collection('notifications').insertOne({
      user: withdrawal.user,
      type: 'withdrawal',
      message: notificationMessage,
      read: false,
      createdAt: new Date()
    });

    return NextResponse.json({
      message: `Đã cập nhật trạng thái yêu cầu rút tiền thành ${status}`
    });

  } catch (error) {
    console.error('Error processing withdrawal request:', error);
    return NextResponse.json({ message: 'Đã xảy ra lỗi khi xử lý yêu cầu rút tiền' }, { status: 500 });
  }
}
