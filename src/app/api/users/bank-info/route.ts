import { NextResponse } from 'next/server';
import { getMongoDb } from '@/lib/db';
import { verifyToken } from '@/lib/auth';
import { ObjectId } from 'mongodb';

// Interface cho bank data với thuộc tính verified
interface BankData {
  name: string;
  accountNumber: string;
  accountHolder: string;
  verified?: boolean;
}

// Interface cho dữ liệu cập nhật
interface UserUpdate {
  bank?: BankData;
}

// Helper function để cập nhật thông tin ngân hàng của người dùng
const updateUserData = async (userId: string, updates: UserUpdate) => {
  try {
    const db = await getMongoDb();
    if (!db) {
      throw new Error('Không thể kết nối đến cơ sở dữ liệu');
    }
    
    // Tạo đối tượng ObjectId từ userId
    const userObjectId = new ObjectId(userId);
    
    // Cập nhật thông tin ngân hàng cho người dùng
    const result = await db.collection('users').findOneAndUpdate(
      { _id: userObjectId },
      { $set: { bank: updates.bank } },
      { returnDocument: 'after' }
    );
    
    if (!result) {
      throw new Error('Không tìm thấy người dùng');
    }
    
    return result;
  } catch (error) {
    console.error('Error updating user bank info:', error);
    throw error;
  }
};

interface UserPayload {
  userId: string;
  isValid: boolean;
  role?: string;
}

// Hàm xác thực người dùng
async function authenticateRequest(request: Request): Promise<{
  user?: { id: string; role?: string };
  error?: string;
  status?: number;
}> {
  // Lấy token từ header hoặc cookie
  const authHeader = request.headers.get('authorization');
  let token = '';

  if (authHeader?.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  } else {
    // Nếu không có trong header, thử lấy từ cookie
    const cookieHeader = request.headers.get('cookie');
    if (cookieHeader) {
      const cookies = cookieHeader.split(';').reduce((acc, cookie) => {
        const [key, value] = cookie.trim().split('=');
        acc[key] = value;
        return acc;
      }, {} as Record<string, string>);
      
      token = cookies.token || '';
    }
  }

  if (!token) {
    return { error: 'Không tìm thấy token xác thực', status: 401 };
  }

  try {
    const payload = await verifyToken(token) as UserPayload;
    if (!payload || !payload.isValid) {
      return { error: 'Token không hợp lệ', status: 401 };
    }
    
    // Lấy thông tin người dùng từ database
    const db = await getMongoDb();
    if (!db) {
      throw new Error('Không thể kết nối đến cơ sở dữ liệu');
    }
    
    const user = await db.collection('users').findOne(
      { _id: new ObjectId(payload.userId) },
      { projection: { _id: 1, role: 1 } }
    );
    
    if (!user) {
      return { error: 'Người dùng không tồn tại', status: 404 };
    }
    
    return { 
      user: { 
        id: user._id.toString(),
        role: user.role
      } 
    };
  } catch (error) {
    console.error('Lỗi xác thực token:', error);
    return { error: 'Lỗi xác thực', status: 401 };
  }
}

export async function POST(request: Request) {
  try {
    // Xác thực người dùng
    const authResult = await authenticateRequest(request);
    if ('error' in authResult) {
      return NextResponse.json(
        { message: authResult.error },
        { status: authResult.status || 401 }
      );
    }
    
    const { user } = authResult;

    // Kiểm tra user tồn tại
    if (!user) {
      return NextResponse.json(
        { message: 'Người dùng không tồn tại' },
        { status: 404 }
      );
    }

    // Lấy dữ liệu từ request body
    const data = await request.json();
    const { name, accountHolder, accountNumber } = data;
    
    // Kiểm tra dữ liệu hợp lệ
    if (!name || !accountHolder || !accountNumber) {
      return NextResponse.json({ message: 'Thông tin không đầy đủ' }, { status: 400 });
    }

    // Cập nhật thông tin ngân hàng (chưa xác minh)
    const updatedUser = await updateUserData(user.id, {
      bank: {
        name,
        accountHolder,
        accountNumber,
        verified: false, // Mặc định là chưa xác minh
      }
    });

    // Trả về kết quả thành công
    return NextResponse.json({
      message: 'Cập nhật thông tin ngân hàng thành công',
      bankInfo: updatedUser.bank,
    });
  } catch (error) {
    console.error('Bank info update error:', error);
    return NextResponse.json(
      { message: 'Lỗi server: ' + (error as Error).message },
      { status: 500 }
    );
  }
}

// API để quản trị viên xác minh thông tin ngân hàng
export async function PUT(request: Request) {
  try {
    // Xác thực người dùng
    const authResult = await authenticateRequest(request);
    if ('error' in authResult) {
      return NextResponse.json(
        { message: authResult.error },
        { status: authResult.status || 401 }
      );
    }
    
    const { user } = authResult;
    
    // Kiểm tra quyền admin
    if (!user || user.role !== 'admin') {
      return NextResponse.json(
        { message: 'Không có quyền truy cập' },
        { status: 403 }
      );
    }

    // Lấy dữ liệu từ request body
    const data = await request.json();
    const { userId, verified } = data;
    
    if (!userId) {
      return NextResponse.json({ message: 'Thiếu thông tin người dùng' }, { status: 400 });
    }

    // Trong API thật, chúng ta sẽ tìm user từ database
    // Ở đây giả lập user đã tồn tại
    const userToUpdate = {
      id: userId,
      bank: {
        name: 'Mock Bank',
        accountNumber: '123456789',
        accountHolder: 'Mock User',
        verified: false
      }
    };

    // Kiểm tra xem người dùng đã cung cấp thông tin ngân hàng chưa
    if (!userToUpdate.bank || !userToUpdate.bank.name) {
      return NextResponse.json({ message: 'Người dùng chưa cung cấp thông tin ngân hàng' }, { status: 400 });
    }

    // Cập nhật trạng thái xác minh
    const updatedUser = await updateUserData(userId, {
      bank: {
        ...userToUpdate.bank,
        verified: verified === true
      }
    });

    return NextResponse.json({
      message: `Đã ${verified ? 'xác minh' : 'hủy xác minh'} thông tin ngân hàng`,
      bankInfo: updatedUser.bank,
    });
  } catch (error) {
    console.error('Bank verification error:', error);
    return NextResponse.json(
      { message: 'Lỗi server: ' + (error as Error).message },
      { status: 500 }
    );
  }
}
