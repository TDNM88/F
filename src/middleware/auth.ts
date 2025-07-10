import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { parseToken } from '@/lib/auth';
import { getMongoDb } from '@/lib/db';
import { ObjectId } from 'mongodb';

export async function authenticateRequest(request: NextRequest) {
  const cookies = request.cookies.get('token')?.value;
  
  if (!cookies) {
    return { user: null, error: 'No token provided' };
  }

  const tokenData = parseToken(cookies);
  if (!tokenData) {
    return { user: null, error: 'Invalid token' };
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

export async function withAuth(handler: any, roles: string[] = ['user']) {
  return async (request: NextRequest) => {
    const { user, error } = await authenticateRequest(request);
    
    if (error) {
      return NextResponse.json(
        { success: false, message: 'Unauthorized: ' + error },
        { status: 401 }
      );
    }

    // Check role if specified
    if (roles.length > 0 && !roles.includes(user.role)) {
      return NextResponse.json(
        { success: false, message: 'Forbidden: Insufficient permissions' },
        { status: 403 }
      );
    }

    // Add user to request object
    request.user = user;
    return handler(request);
  };
}
