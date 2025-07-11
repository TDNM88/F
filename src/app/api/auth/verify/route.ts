import { NextResponse, NextRequest } from 'next/server';

// This endpoint verifies the authentication status of the current user
// Bỏ qua middleware withAuth để tự xử lý xác thực
export const GET = async (request: NextRequest) => {
  try {
    // Lấy token từ header Authorization Bearer thay vì cookie
    const authHeader = request.headers.get('Authorization');
    let token: string | null = null;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
      console.log('Token received from Authorization header', { token: token?.substring(0, 10) + '...' });
    } else {
      console.log('No Authorization header or invalid format');
    }

    // Vẫn hỗ trợ token từ cookie cho các phiên cũ (có thể bỏ sau)
    if (!token) {
      token = request.cookies.get('token')?.value || null;
      if (token) {
        console.log('Token received from cookie (fallback)', { token: token.substring(0, 10) + '...' });
      }
    }

    if (!token) {
      console.log('No token provided in Authorization header or cookie');
      return NextResponse.json({ isValid: false, error: 'No token provided' }, { status: 401 });
    }

    // Kiểm tra token hợp lệ - cần thay thế bằng logic kiểm tra token thực sự
    // Ví dụ: kiểm tra với cơ sở dữ liệu hoặc dịch vụ xác thực
    // Ở đây tạm thời giả định token hợp lệ nếu tồn tại
    if (token) {
      // Giả lập thông tin người dùng - thay thế bằng dữ liệu thực tế
      return NextResponse.json({
        isValid: true,
        user: {
          id: 'user-id',
          username: 'username',
          email: 'user@example.com',
          role: 'user',
          balance: { available: 0, frozen: 0 }
        }
      });
    } else {
      return NextResponse.json({ isValid: false, error: 'Invalid token' }, { status: 401 });
    }
  } catch (error) {
    console.error('Verify error:', error);
    return NextResponse.json(
      { isValid: false, message: 'Internal server error' },
      { status: 500 }
    );
  }
};
