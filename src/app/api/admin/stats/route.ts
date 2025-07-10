import { NextResponse } from 'next/server';
import { getMongoDb } from '@/lib/db';
import { verifyToken } from '@/lib/auth';
import { ObjectId } from 'mongodb';

interface StatsResponse {
  success: boolean;
  data: {
    newUsers: number;
    totalDeposits: number;
    totalWithdrawals: number;
    totalUsers: number;
    activeUsers: number;
    totalBalance: number;
  };
}

export async function GET(request: Request) {
  try {
    // Verify admin authentication
    const authHeader = request.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new NextResponse(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
    }

    const token = authHeader.split(' ')[1];
    const user = await verifyToken(token);
    
    if (!user || user.role !== 'admin') {
      return new NextResponse(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const startDate = searchParams.get('startDate');
    const endDate = searchParams.get('endDate');

    // Create date range filter
    const dateFilter: any = {};
    if (startDate) {
      dateFilter.$gte = new Date(startDate);
    }
    if (endDate) {
      dateFilter.$lte = new Date(endDate);
    }

    // Get MongoDB connection
    const db = await getMongoDb();
    if (!db) {
      throw new Error('Database connection failed');
    }

    // Get stats in parallel
    const [
      newUsersCount,
      totalDeposits,
      totalWithdrawals,
      totalUsersCount,
      totalActiveUsers,
      totalBalance
    ] = await Promise.all([
      // New users count
      db.collection('users').countDocuments({
        ...(Object.keys(dateFilter).length > 0 && { createdAt: dateFilter })
      }),
      
      // Total deposits
      db.collection('transactions').aggregate([
        {
          $match: {
            type: 'DEPOSIT',
            status: 'COMPLETED',
            ...(Object.keys(dateFilter).length > 0 && { createdAt: dateFilter })
          }
        },
        {
          $group: {
            _id: null,
            total: { $sum: '$amount' }
          }
        }
      ]).toArray(),
      
      // Total withdrawals
      db.collection('transactions').aggregate([
        {
          $match: {
            type: 'WITHDRAWAL',
            status: 'COMPLETED',
            ...(Object.keys(dateFilter).length > 0 && { createdAt: dateFilter })
          }
        },
        {
          $group: {
            _id: null,
            total: { $sum: '$amount' }
          }
        }
      ]).toArray(),
      
      // Total users count
      db.collection('users').countDocuments(),
      
      // Total active users (users who logged in within last 30 days)
      db.collection('users').countDocuments({
        lastLogin: {
          $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
        }
      }),
      
      // Total platform balance
      db.collection('users').aggregate([
        {
          $group: {
            _id: null,
            total: { $sum: '$balance.available' }
          }
        }
      ]).toArray()
    ]);

    // Extract totals from aggregation results
    const depositsTotal = totalDeposits[0]?.total || 0;
    const withdrawalsTotal = totalWithdrawals[0]?.total || 0;
    const balanceTotal = totalBalance[0]?.total || 0;

    const response: StatsResponse = {
      success: true,
      data: {
        newUsers: newUsersCount,
        totalDeposits: depositsTotal,
        totalWithdrawals: withdrawalsTotal,
        totalUsers: totalUsersCount,
        activeUsers: totalActiveUsers,
        totalBalance: balanceTotal
      }
    };

    return NextResponse.json(response);

  } catch (error) {
    console.error('Error fetching admin stats:', error);
    return new NextResponse(
      JSON.stringify({ 
        error: 'Internal Server Error',
        details: error instanceof Error ? error.message : 'Unknown error'
      }), 
      { status: 500 }
    );
  }
}
