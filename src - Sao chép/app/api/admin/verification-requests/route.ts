import { NextRequest, NextResponse } from 'next/server';
import { verifyToken } from '@/lib/auth';
import { ObjectId } from 'mongodb';
import clientPromise from '@/lib/mongodb';

interface UserDocument {
  _id: ObjectId;
  username: string;
  fullName?: string;
  verification?: {
    cccdFront?: string;
    cccdBack?: string;
    verified?: boolean;
  };
  updatedAt: Date;
}

export async function GET(req: NextRequest) {
  try {
    // Xác thực admin
    const token = req.headers.get('authorization')?.split(' ')[1];
    if (!token) {
      return NextResponse.json({ message: 'Bạn cần đăng nhập' }, { status: 401 });
    }

    const user = await verifyToken(token);
    if (!user || user.role !== 'admin') {
      return NextResponse.json({ message: 'Không có quyền truy cập' }, { status: 403 });
    }

    // Kết nối database
    const client = await clientPromise;
    const db = client.db();
    
    // Lấy danh sách người dùng đã upload đủ 2 ảnh nhưng chưa được xác minh
    const requests: UserDocument[] = await db.collection('users').aggregate([
      {
        $match: {
          'verification.cccdFront': { $exists: true, $ne: '' },
          'verification.cccdBack': { $exists: true, $ne: '' },
          'verification.verified': { $ne: true }
        }
      },
      {
        $project: {
          username: 1,
          fullName: 1,
          'verification.cccdFront': 1,
          'verification.cccdBack': 1,
          'verification.verified': 1,
          updatedAt: 1
        }
      },
      { $sort: { updatedAt: -1 } }
    ]).toArray();

    return NextResponse.json({
      success: true,
      requests: requests.map((r: UserDocument) => ({
        _id: r._id.toString(),
        username: r.username,
        fullName: r.fullName,
        updatedAt: r.updatedAt,
        verification: {
          cccdFront: r.verification?.cccdFront || '',
          cccdBack: r.verification?.cccdBack || '',
          verified: r.verification?.verified || false
        }
      }))
    });

  } catch (error) {
    console.error('Error fetching verification requests:', error);
    return NextResponse.json({
      success: false,
      message: 'Đã xảy ra lỗi khi lấy danh sách yêu cầu xác minh'
    }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  try {
    // Xác thực admin
    const token = req.headers.get('authorization')?.split(' ')[1];
    if (!token) {
      return NextResponse.json({ message: 'Bạn cần đăng nhập' }, { status: 401 });
    }

    const user = await verifyToken(token);
    if (!user || user.role !== 'admin') {
      return NextResponse.json({ message: 'Không có quyền truy cập' }, { status: 403 });
    }

    const { userId, status } = await req.json();
    
    if (!userId || typeof status !== 'boolean') {
      return NextResponse.json({ 
        success: false,
        message: 'Thiếu thông tin yêu cầu' 
      }, { status: 400 });
    }

    if (!ObjectId.isValid(userId)) {
      return NextResponse.json({
        success: false,
        message: 'ID người dùng không hợp lệ'
      }, { status: 400 });
    }

    // Kết nối database
    const client = await clientPromise;
    const db = client.db();
    
    // Cập nhật trạng thái xác minh
    const result = await db.collection('users').updateOne(
      { 
        _id: new ObjectId(userId),
        'verification.cccdFront': { $exists: true, $ne: '' },
        'verification.cccdBack': { $exists: true, $ne: '' }
      },
      { 
        $set: { 
          'verification.verified': status,
          'verification.verifiedAt': new Date(),
          'verification.verifiedBy': user.id
        } 
      }
    );

    if (result.matchedCount === 0) {
      return NextResponse.json({
        success: false,
        message: 'Không tìm thấy yêu cầu xác minh hợp lệ'
      }, { status: 404 });
    }

    return NextResponse.json({
      success: true,
      message: `Đã ${status ? 'chấp nhận' : 'từ chối'} yêu cầu xác minh`
    });

  } catch (error) {
    console.error('Error updating verification status:', error);
    return NextResponse.json({
      success: false,
      message: 'Đã xảy ra lỗi khi cập nhật trạng thái xác minh'
    }, { status: 500 });
  }
}
