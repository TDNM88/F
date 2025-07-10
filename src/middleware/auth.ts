import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { parseToken } from '@/lib/auth';
import { getMongoDb } from '@/lib/db';
import { ObjectId } from 'mongodb';

/**
 * Xác thực yêu cầu dựa trên token trong cookie
 * 
 * @param request NextRequest object từ NextJS
 * @returns Object chứa user data nếu xác thực thành công hoặc null và thông báo lỗi nếu thất bại
 */
export async function authenticateRequest(request: NextRequest) {
  try {
    const token = request.cookies.get('token')?.value;
    
    console.debug('Authenticating request:', { 
      hasToken: !!token, 
      url: request.url,
      cookieCount: request.cookies.getAll().length,
      cookieKeys: Array.from(request.cookies.getAll()).map(c => c.name),
    });
    
    if (!token) {
      console.debug('Authentication failed: No token provided');
      return { user: null, error: 'No token provided' };
    }
    
    // Debug log token content length without revealing it
    console.debug(`Token found with length: ${token.length}`);

    const tokenData = parseToken(token);
    if (!tokenData) {
      console.debug('Authentication failed: Invalid token format');
      return { user: null, error: 'Invalid token format' };
    }
    
    console.debug('Token parsed successfully:', { userId: tokenData.userId });
  
    // Check token expiry (7 days)
    const tokenAge = Date.now() - tokenData.timestamp;
    const maxTokenAge = 7 * 24 * 60 * 60 * 1000; // 7 days
    
    if (tokenAge > maxTokenAge) {
      console.debug('Authentication failed: Token expired');
      return { user: null, error: 'Token expired' };
    }

    // Tìm user từ database
    const db = await getMongoDb();
    const user = await db.collection('users').findOne({
      _id: new ObjectId(tokenData.userId)
    });

    if (!user) {
      console.debug('Authentication failed: User not found');
      return { user: null, error: 'User not found' };
    }

    // Remove sensitive data
    const { password, ...userWithoutPassword } = user;
    console.debug('Authentication successful for user:', { username: user.username });
    return { user: userWithoutPassword, error: null };
  } catch (error) {
    console.error('Authentication error:', error);
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
    console.debug('withAuth middleware called for URL:', request.url);
    const { user, error } = await authenticateRequest(request);
    
    if (error || !user) {
      console.debug('Authentication failed:', { error, hasUser: !!user });
      return NextResponse.json(
        { success: false, message: 'Unauthorized: ' + (error || 'No user found') },
        { status: 401 }
      );
    }

    // Check role if specified
    if (roles.length > 0 && user && !roles.includes(user.role)) {
      console.debug('Authorization failed: Insufficient permissions', {
        userRole: user.role, 
        requiredRoles: roles
      });
      return NextResponse.json(
        { success: false, message: 'Forbidden: Insufficient permissions' },
        { status: 403 }
      );
    }

    console.debug('User authenticated successfully:', {
      username: user.username,
      role: user.role,
      path: request.url
    });

    // Create a new request object with the user attached to avoid modifying NextRequest directly
    const authRequest = request as any;
    authRequest.user = user;
    
    try {
      // Make sure handler is properly awaited to prevent Promise errors
      const result = await handler(authRequest);
      return result;
    } catch (error) {
      console.error('Handler error in withAuth:', error);
      return NextResponse.json(
        { 
          success: false, 
          message: 'Internal server error',
          _debug: process.env.NODE_ENV !== 'production' ? {
            error: error instanceof Error ? error.message : String(error),
          } : undefined
        },
        { status: 500 }
      );
    }
  };
}
