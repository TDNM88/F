import { NextResponse } from 'next/server';
import { getMongoDb } from '@/lib/db';
import { getToken } from 'next-auth/jwt';
import { authConfig } from '@/auth.config';
import { NextRequest } from 'next/server';
import { parseSessionId } from '@/lib/sessionUtils';

export async function GET(request: NextRequest) {
  try {
    const token = await getToken({ 
      req: request,
      secret: process.env.NEXTAUTH_SECRET
    });
    if (!token) {
      return NextResponse.json(
        { success: false, message: 'Unauthorized' },
        { status: 401 }
      );
    }

    const { searchParams } = new URL(request.url);
    const page = parseInt(searchParams.get('page') || '1');
    const limit = parseInt(searchParams.get('limit') || '10');
    const skip = (page - 1) * limit;

    const db = await getMongoDb();
    if (!db) {
      throw new Error('Could not connect to database');
    }

    // Get total count for pagination
    const total = await db.collection('admin_trades').countDocuments();
    
    // Get paginated results
    const sessions = await db
      .collection('admin_trades')
      .find()
      .sort({ startTime: -1 })
      .skip(skip)
      .limit(limit)
      .toArray();

    return NextResponse.json({
      success: true,
      data: sessions,
      pagination: {
        total,
        page,
        totalPages: Math.ceil(total / limit),
        limit
      }
    });

  } catch (error) {
    console.error('Error fetching trading sessions:', error);
    return NextResponse.json(
      { success: false, message: 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const token = await getToken({ 
      req: request,
      secret: process.env.NEXTAUTH_SECRET
    });
    if (!token) {
      return NextResponse.json(
        { success: false, message: 'Unauthorized' },
        { status: 401 }
      );
    }

    const sessionData = await request.json();
    let { sessionId, result: tradeResult, startTime, endTime, status } = sessionData;
    
    // Nếu không có sessionId, tạo mới dựa trên thời gian hiện tại
    if (!sessionId && status === 'active') {
      const now = new Date();
      const year = now.getFullYear().toString().slice(-2);
      const month = (now.getMonth() + 1).toString().padStart(2, '0');
      const day = now.getDate().toString().padStart(2, '0');
      const hours = now.getHours().toString().padStart(2, '0');
      const minutes = now.getMinutes().toString().padStart(2, '0');
      sessionId = `${year}${month}${day}${hours}${minutes}`;
      
      // Cập nhật lại thời gian nếu cần
      if (!startTime) startTime = now.toISOString();
      if (!endTime) endTime = new Date(now.getTime() + 60000).toISOString(); // Thêm 1 phút
    }

    if (!sessionId || !tradeResult || !startTime || !endTime || !status) {
      return NextResponse.json(
        { success: false, message: 'Missing required fields' },
        { status: 400 }
      );
    }

    const db = await getMongoDb();
    if (!db) {
      throw new Error('Could not connect to database');
    }

    // Check if session already exists
    const existingSession = await db.collection('admin_trades').findOne({ sessionId });
    let dbResult;

    if (existingSession) {
      // Update existing session
      dbResult = await db.collection('admin_trades').updateOne(
        { sessionId },
        { $set: { result: tradeResult, startTime, endTime, status } }
      );
    } else {
      // Create new session
      dbResult = await db.collection('admin_trades').insertOne({
        sessionId,
        result: tradeResult,
        startTime,
        endTime,
        status,
        createdAt: new Date(),
        updatedAt: new Date()
      });
    }

    return NextResponse.json({
      success: true,
      data: {
        sessionId,
        result: tradeResult,
        startTime,
        endTime,
        status
      }
    });

  } catch (error) {
    console.error('Error saving trading session:', error);
    return NextResponse.json(
      { success: false, message: 'Internal server error' },
      { status: 500 }
    );
  }
}
