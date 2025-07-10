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

    const authResult = await verifyToken(token);
    if (!authResult || !authResult.isValid) {
      return NextResponse.json({ message: 'Token không hợp lệ' }, { status: 401 });
    }
    
    // Lấy thông tin người dùng từ database và kiểm tra quyền admin
    const db = await getMongoDb();
    const user = await db.collection('users').findOne({ _id: new ObjectId(authResult.userId) });
    if (!user) {
      return NextResponse.json({ message: 'Không tìm thấy thông tin người dùng' }, { status: 404 });
    }

    // Kiểm tra quyền admin
    if (user.role !== 'admin') {
      return NextResponse.json({ message: 'Bạn không có quyền truy cập' }, { status: 403 });
    }

    // Parse query params
    const url = new URL(req.url);
    const page = parseInt(url.searchParams.get('page') || '1');
    const limit = parseInt(url.searchParams.get('limit') || '50');
    const status = url.searchParams.get('status');
    const customer = url.searchParams.get('customer');
    const startDate = url.searchParams.get('startDate');
    const endDate = url.searchParams.get('endDate');
    const skip = (page - 1) * limit;

    // Tạo filter
    const filter: any = {};
    if (status && status !== 'all') {
      filter.status = status;
    }
    
    // Lọc theo tên khách hàng
    if (customer) {
      filter['userDetails.username'] = { $regex: customer, $options: 'i' };
    }
    
    // Lọc theo ngày
    const dateFilter: any = {};
    if (startDate) {
      dateFilter.$gte = new Date(startDate);
    }
    if (endDate) {
      dateFilter.$lte = new Date(new Date(endDate).setHours(23, 59, 59, 999));
    }
    if (Object.keys(dateFilter).length > 0) {
      filter.createdAt = dateFilter;
    }

    // Pipeline aggregation để lấy thông tin yêu cầu rút tiền
    const pipeline: any[] = [
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
          bankName: 1,
          bankAccountNumber: 1,
          accountHolder: 1,
          status: 1,
          notes: 1,
          createdAt: 1,
          updatedAt: 1,
          customer: {
            $ifNull: ['$userDetails.username', 'N/A']
          },
          time: '$createdAt'
        }
      }
    ];

    const withdrawals = await db.collection('withdrawals').aggregate(pipeline).toArray();

    // Lấy tổng số bản ghi để phân trang
    const total = await db.collection('withdrawals').countDocuments(filter);

    return NextResponse.json({
      success: true,
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

    const authResult = await verifyToken(token);
    if (!authResult || !authResult.isValid) {
      return NextResponse.json({ message: 'Token không hợp lệ' }, { status: 401 });
    }
    
    // Lấy thông tin người dùng từ database và kiểm tra quyền admin
    const db = await getMongoDb();
    const user = await db.collection('users').findOne({ _id: new ObjectId(authResult.userId) });
    if (!user) {
      return NextResponse.json({ message: 'Không tìm thấy thông tin người dùng' }, { status: 404 });
    }

    // Parse request body
    const { withdrawalId, status, notes } = await req.json();

    if (!withdrawalId || !status) {
      return NextResponse.json({ message: 'Thiếu thông tin cần thiết' }, { status: 400 });
    }

    if (!['Chờ duyệt', 'Đã duyệt', 'Từ chối'].includes(status)) {
      return NextResponse.json({ message: 'Trạng thái không hợp lệ. Vui lòng chọn một trong các trạng thái: Chờ duyệt, Đã duyệt, Từ chối' }, { status: 400 });
    }

    // Kiểm tra quyền admin
    if (user.role !== 'admin') {
      return NextResponse.json({ message: 'Bạn không có quyền truy cập' }, { status: 403 });
    }

    // Lấy thông tin yêu cầu rút tiền
    const withdrawalIdObject = new ObjectId(withdrawalId);
    const withdrawal = await db.collection('withdrawals').findOne({ _id: withdrawalIdObject });
    if (!withdrawal) {
      return NextResponse.json({ message: 'Không tìm thấy yêu cầu rút tiền' }, { status: 404 });
    }

    // Nếu yêu cầu đã được hoàn thành hoặc từ chối
    if (withdrawal.status === 'Đã duyệt' || withdrawal.status === 'Từ chối') {
      return NextResponse.json({ message: 'Yêu cầu này đã được xử lý hoàn tất' }, { status: 400 });
    }

    // Nếu chuyển từ Chờ duyệt sang Đã duyệt, kiểm tra lại số dư
    if (status === 'Đã duyệt') {
      const userAccount = await db.collection('users').findOne({ _id: withdrawal.user });
      if (!userAccount) {
        return NextResponse.json({ 
          message: 'Không tìm thấy tài khoản người dùng' 
        }, { status: 404 });
      }
      
      if (userAccount.balance < withdrawal.amount) {
        return NextResponse.json({ 
          message: 'Số dư của người dùng không đủ để thực hiện giao dịch' 
        }, { status: 400 });
      }
    }

    // Cập nhật trạng thái yêu cầu
    await db.collection('withdrawals').updateOne(
      { _id: new ObjectId(withdrawalId) },
      {
        $set: {
          status,
          notes: notes || withdrawal.notes || '',
          processedBy: new ObjectId(user._id),
          processedAt: new Date(),
          updatedAt: new Date()
        }
      }
    );

    // Nếu từ chối, hoàn lại tiền cho người dùng
    if (status === 'Từ chối') {
      await db.collection('users').updateOne(
        { _id: withdrawal.user },
        { $inc: { balance: withdrawal.amount } }
      );
    }
    
    // Nếu duyệt, trừ tiền khỏi tài khoản
    if (status === 'Đã duyệt') {
      await db.collection('users').updateOne(
        { _id: withdrawal.user },
        { $inc: { balance: -withdrawal.amount } }
      );
    }

    // Tạo thông báo cho người dùng
    const notificationMessage = 
      status === 'Chờ duyệt' ? 'Yêu cầu rút tiền của bạn đang chờ xử lý' :
      status === 'Đã duyệt' ? `Yêu cầu rút tiền ${withdrawal.amount.toLocaleString()}đ của bạn đã được duyệt` :
      `Yêu cầu rút tiền ${withdrawal.amount.toLocaleString()}đ của bạn đã bị từ chối`;

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
