import { NextResponse } from 'next/server';
import { parseToken } from '@/lib/auth';
import { getMongoDb } from '@/lib/db';
import { ObjectId } from 'mongodb';

export async function GET(request: Request) {
  try {
    const authHeader = request.headers.get('authorization');
    const token = authHeader?.split(' ')[1];
    
    if (!token) {
      return NextResponse.json(
        { valid: false, message: 'No token provided' },
        { status: 401 }
      );
    }
    
    // Parse the token to get user ID
    const tokenData = parseToken(token);
    if (!tokenData) {
      return NextResponse.json(
        { valid: false, message: 'Invalid token format' },
        { status: 401 }
      );
    }
    
    // Connect to database
    const db = await getMongoDb();
    const usersCollection = db.collection('users');
    
    // Find user by ID
    const user = await usersCollection.findOne({ _id: new ObjectId(tokenData.userId) });
    
    if (!user) {
      return NextResponse.json(
        { valid: false, message: 'User not found' },
        { status: 404 }
      );
    }
    
    // Check if token is still valid (not expired)
    const tokenAge = Date.now() - tokenData.timestamp;
    const maxTokenAge = 30 * 24 * 60 * 60 * 1000; // 30 days
    
    if (tokenAge > maxTokenAge) {
      return NextResponse.json(
        { valid: false, message: 'Token expired' },
        { status: 401 }
      );
    }
    
    // Return user data without sensitive information
    const { password, ...userData } = user;
    
    return NextResponse.json({ 
      valid: true,
      user: {
        id: user._id.toString(),
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
    
  } catch (error) {
    console.error('Token verification error:', error);
    return NextResponse.json(
      { valid: false, message: 'Error verifying token' },
      { status: 500 }
    );
  }
}
