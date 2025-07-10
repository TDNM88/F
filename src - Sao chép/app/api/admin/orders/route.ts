import { NextResponse } from 'next/server';
import { getMongoDb } from '@/lib/db';
import { getToken } from 'next-auth/jwt';
import { NextRequest } from 'next/server';

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
    const startDate = searchParams.get('startDate') || '';
    const endDate = searchParams.get('endDate') || '';
    const skip = (page - 1) * limit;

    const db = await getMongoDb();
    if (!db) {
      throw new Error('Could not connect to database');
    }

    // Build query
    const query: any = {};
    if (startDate && endDate) {
      query.createdAt = {
        $gte: new Date(startDate),
        $lte: new Date(endDate)
      };
    }

    // Get total count for pagination
    const total = await db.collection('orders').countDocuments(query);
    
    // Get paginated results
    const orders = await db
      .collection('orders')
      .find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .toArray();

    return NextResponse.json({
      success: true,
      data: {
        orders,
        pagination: {
          total,
          page,
          totalPages: Math.ceil(total / limit),
          limit
        }
      }
    });

  } catch (error) {
    console.error('Error fetching orders:', error);
    return NextResponse.json(
      { success: false, message: 'Internal server error' },
      { status: 500 }
    );
  }
}
