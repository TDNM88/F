import { NextRequest, NextResponse } from 'next/server';
import { getMongoDb } from '@/lib/db';
import { ObjectId } from 'mongodb';
import { verifyToken } from '@/lib/auth';

// API để lấy danh sách yêu cầu nạp tiền (dành cho Admin)
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
          status: 1,
          proofImage: 1,
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

    const deposits = await db.collection('deposits').aggregate(pipeline).toArray();

    // Lấy tổng số bản ghi để phân trang
    const total = await db.collection('deposits').countDocuments(filter);

    return NextResponse.json({
      deposits,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit)
    });

  } catch (error) {
    console.error('Error fetching deposit requests:', error);
    return NextResponse.json({ message: 'Đã xảy ra lỗi khi lấy danh sách yêu cầu nạp tiền' }, { status: 500 });
  }
}

// API để phê duyệt hoặc từ chối yêu cầu nạp tiền
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
    const { depositId, status, notes } = await req.json();

    if (!depositId || !status) {
      return NextResponse.json({ message: 'Thiếu thông tin cần thiết' }, { status: 400 });
    }

    if (!['approved', 'rejected'].includes(status)) {
      return NextResponse.json({ message: 'Trạng thái không hợp lệ' }, { status: 400 });
    }

    // Kết nối DB
    const db = await getMongoDb();

    // Kiểm tra quyền admin
    if (user.role !== 'admin') {
      return NextResponse.json({ message: 'Bạn không có quyền truy cập' }, { status: 403 });
    }

    // Lấy thông tin yêu cầu nạp tiền
    const deposit = await db.collection('deposits').findOne({ _id: new ObjectId(depositId) });
    if (!deposit) {
      return NextResponse.json({ message: 'Không tìm thấy yêu cầu nạp tiền' }, { status: 404 });
    }

    // Nếu yêu cầu đã được xử lý
    if (deposit.status !== 'pending') {
      return NextResponse.json({ message: 'Yêu cầu này đã được xử lý' }, { status: 400 });
    }

    // Cập nhật trạng thái yêu cầu
    await db.collection('deposits').updateOne(
      { _id: new ObjectId(depositId) },
      {
        $set: {
          status,
          notes: notes || '',
          approvedBy: new ObjectId(user.id),
          approvedAt: new Date(),
          updatedAt: new Date()
        }
      }
    );

    // Nếu phê duyệt, cộng tiền vào tài khoản người dùng
    if (status === 'approved') {
      await db.collection('users').updateOne(
        { _id: deposit.user },
        { $inc: { balance: deposit.amount } }
      );
    }

    return NextResponse.json({
      message: `Đã ${status === 'approved' ? 'phê duyệt' : 'từ chối'} yêu cầu nạp tiền`
    });

  } catch (error) {
    console.error('Error processing deposit request:', error);
    return NextResponse.json({ message: 'Đã xảy ra lỗi khi xử lý yêu cầu nạp tiền' }, { status: 500 });
  }
}
