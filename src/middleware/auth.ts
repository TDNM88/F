import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { parseToken } from '@/lib/auth';
import { getMongoDb } from '@/lib/db';
import { ObjectId } from 'mongodb';

// Thời gian sống của token - 7 ngày
const TOKEN_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds

// Helper để kiểm soát logging
const debugLog = (message: string, data?: any) => {
  if (process.env.DEBUG_AUTH === 'true' || process.env.NODE_ENV !== 'production') {
    console.debug(`[Auth Debug] ${message}`, data);
  }
};

/**
 * Xác thực yêu cầu dựa trên token trong cookie
 * 
 * @param request NextRequest object từ NextJS
 * @returns Object chứa user data nếu xác thực thành công hoặc null và thông báo lỗi nếu thất bại
 */
export async function authenticateRequest(request: NextRequest) {
  try {
    const token = request.cookies.get('token')?.value;
    
    debugLog('Authenticating request', { 
      hasToken: !!token, 
      url: request.url.split('?')[0], // Lấy URL cơ bản không có query params
      cookieCount: request.cookies.getAll().length,
      // Không log tên các cookie - cải thiện bảo mật
    });
    
    if (!token) {
      debugLog('Authentication failed', { reason: 'No token provided' });
      return { user: null, error: 'No token provided' };
    }
    
    // Debug log token content length without revealing it
    debugLog('Token found', { length: token.length });

    const tokenData = parseToken(token);
    if (!tokenData) {
      debugLog('Authentication failed', { reason: 'Invalid token format' });
      return { user: null, error: 'Invalid token format' };
    }
    
    // Giảm thiểu log thông tin nhạy cảm
    debugLog('Token parsed successfully', { 
      userId: tokenData.userId ? tokenData.userId.substring(0, 4) + '...' : null 
    });
  
    // Check token expiry sử dụng hằng số đã định nghĩa
    const tokenAge = Date.now() - tokenData.timestamp;
    
    if (tokenAge > TOKEN_MAX_AGE_MS) {
      debugLog('Authentication failed', { 
        reason: 'Token expired', 
        age: Math.floor(tokenAge / 1000 / 60 / 60) + ' hours'
      });
      return { user: null, error: 'Token expired' };
    }

    // Tìm user từ database với xử lý lỗi tốt hơn
    try {
      const db = await getMongoDb();
      const user = await db.collection('users').findOne({
        _id: new ObjectId(tokenData.userId)
      });

      if (!user) {
        debugLog('Authentication failed', { reason: 'User not found' });
        return { user: null, error: 'User not found' };
      }

      // Remove sensitive data
      const { password, ...userWithoutPassword } = user;
      debugLog('Authentication successful', { 
        username: user.username?.substring(0, 2) + '***', 
        role: user.role 
      });
      return { user: userWithoutPassword, error: null };
    } catch (dbError) {
      // Xử lý riêng lỗi database
      debugLog('Database error during authentication', { 
        error: dbError instanceof Error ? dbError.message : 'Unknown error' 
      });
      return { user: null, error: 'Database error during authentication' };
    }
  } catch (error) {
    // Xử lý các lỗi khác trong quá trình xác thực
    console.error('Authentication error:', error instanceof Error ? error.message : 'Unknown error');
    return { user: null, error: 'Authentication failed' };
  }
}

/**
 * HOC middleware để bảo vệ API routes yêu cầu xác thực
 * 
 * @param handler Hàm xử lý API route cần bảo vệ
 * @param roles Mảng các vai trò được phép truy cập (mặc định: ['user'])
 * @returns Wrapped handler function
 */
export function withAuth(handler: Function, roles: string[] = ['user']) {
  return async (request: NextRequest) => {
    // Sử dụng debugLog thay cho console.debug
    debugLog('withAuth middleware called', {
      url: request.url.split('?')[0], // Không log query parameters vì có thể chứa thông tin nhạy cảm
      method: request.method,
      roles: roles,
    });
    
    const { user, error } = await authenticateRequest(request);
    
    if (error || !user) {
      debugLog('Authentication failed in middleware', { error });
      return NextResponse.json(
        { success: false, message: 'Unauthorized: ' + (error || 'No user found') },
        { status: 401 }
      );
    }

    // Check role if specified
    if (roles.length > 0 && user && !roles.includes(user.role)) {
      debugLog('Authorization failed', {
        requiredRoles: roles,
        // Không log thông tin cụ thể về người dùng
        hasValidRole: false
      });
      return NextResponse.json(
        { success: false, message: 'Forbidden: Insufficient permissions' },
        { status: 403 }
      );
    }

    debugLog('User authenticated successfully', {
      // Bảo mật thông tin người dùng
      role: user.role,
      path: request.url.split('?')[0]
    });

    // Create a new request object with the user attached to avoid modifying NextRequest directly
    const authRequest = request as any;
    authRequest.user = user;
    
    try {
      // Make sure handler is properly awaited to prevent Promise errors
      const result = await handler(authRequest);
      return result;
    } catch (error) {
      // Xử lý lỗi tốt hơn và không để lộ thông tin nhạy cảm
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      console.error('Handler error in withAuth:', errorMessage);
      
      // Chỉ trả về thông tin lỗi chi tiết trong môi trường development
      return NextResponse.json(
        { 
          success: false, 
          message: 'Internal server error',
          _debug: process.env.DEBUG_AUTH === 'true' || process.env.NODE_ENV !== 'production' ? {
            error: errorMessage,
            path: request.url.split('?')[0]
          } : undefined
        },
        { status: 500 }
      );
    }
  };
}
