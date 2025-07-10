import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { parseToken } from '@/lib/auth';
import { getMongoDb } from '@/lib/db';
import { ObjectId } from 'mongodb';

export async function authenticateRequest(request: NextRequest) {
  const token = request.cookies.get('token')?.value;
  
  console.debug('Authenticating request:', { 
    hasToken: !!token, 
    url: request.url,
    cookieKeys: Array.from(request.cookies.getAll()).map(c => c.name),
  });
  
  if (!token) {
    console.debug('Authentication failed: No token provided');
    return { user: null, error: 'No token provided' };
  }

  const tokenData = parseToken(token);
  if (!tokenData) {
    console.debug('Authentication failed: Invalid token format');
    return { user: null, error: 'Invalid token format' };
  }

  // Check token expiry (7 days)
  const tokenAge = Date.now() - tokenData.timestamp;
  const maxTokenAge = 7 * 24 * 60 * 60 * 1000; // 7 days
  
  if (tokenAge > maxTokenAge) {
    return { user: null, error: 'Token expired' };
  }

  try {
    const db = await getMongoDb();
    const user = await db.collection('users').findOne({
      _id: new ObjectId(tokenData.userId)
    });

    if (!user) {
      return { user: null, error: 'User not found' };
    }

    // Remove sensitive data
    const { password, ...userWithoutPassword } = user;
    return { user: userWithoutPassword, error: null };
  } catch (error) {
    console.error('Authentication error:', error);
    return { user: null, error: 'Authentication failed' };
  }
}

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
      return NextResponse.json(
        { success: false, message: 'Forbidden: Insufficient permissions' },
        { status: 403 }
      );
    }

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
        { success: false, message: 'Internal server error' },
        { status: 500 }
      );
    }
  };
}
