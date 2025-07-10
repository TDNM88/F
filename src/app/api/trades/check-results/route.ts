import { NextResponse } from 'next/server';
import { getMongoDb } from '@/lib/db';
import { verifyToken } from '@/lib/auth';
import { ObjectId } from 'mongodb';

export async function POST(req: Request) {
  try {
    const authHeader = req.headers.get('authorization');
    if (!authHeader) {
      return NextResponse.json({ message: 'Unauthorized' }, { status: 401 });
    }

    const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : authHeader;
    const user = await verifyToken(token);
    
    if (!user?.id) {
      return NextResponse.json({ message: 'Invalid token' }, { status: 401 });
    }

    const { sessionId } = await req.json();
    if (!sessionId) {
      return NextResponse.json({ message: 'Session ID is required' }, { status: 400 });
    }

    const db = await getMongoDb();
    
    // Lấy kết quả phiên từ admin
    const session = await db.collection('sessions').findOne({ sessionId });
    if (!session) {
      return NextResponse.json({ message: 'Session not found' }, { status: 404 });
    }

    // Nếu chưa có kết quả
    if (!session.result) {
      return NextResponse.json({ hasResult: false });
    }

    // Cập nhật tất cả các lệnh chưa có kết quả cho phiên này
    const trades = await db.collection('trades')
      .find({ 
        sessionId,
        status: 'pending',
        result: null
      })
      .toArray();

    const sessionClient = db.startSession();
    try {
      await sessionClient.withTransaction(async () => {
        for (const trade of trades) {
          const isWin = trade.direction.toLowerCase() === session.result?.toLowerCase();
          const profit = isWin ? trade.amount * 1.9 : 0; // 1.9x tiền thắng
          
          // Cập nhật trạng thái lệnh
          await db.collection('trades').updateOne(
            { _id: trade._id },
            {
              $set: {
                status: 'completed',
                result: isWin ? 'win' : 'lose',
                profit,
                updatedAt: new Date()
              }
            },
            { session: sessionClient }
          );

          // Cập nhật số dư tài khoản
          if (isWin) {
            await db.collection('users').updateOne(
              { _id: trade.userId },
              {
                $inc: {
                  'balance.available': trade.amount * 2.9, // Trả lại tiền cược + tiền thắng
                  'balance.frozen': -trade.amount
                }
              },
              { session: sessionClient }
            );
          } else {
            await db.collection('users').updateOne(
              { _id: trade.userId },
              {
                $inc: {
                  'balance.frozen': -trade.amount
                }
              },
              { session: sessionClient }
            );
          }
        }
      });
    } finally {
      await sessionClient.endSession();
    }

    // Lấy lại danh sách lệnh đã cập nhật
    const updatedTrades = await db.collection('trades')
      .find({ sessionId })
      .sort({ createdAt: -1 })
      .toArray();

    return NextResponse.json({
      hasResult: true,
      result: session.result,
      trades: updatedTrades.map(trade => ({
        ...trade,
        _id: trade._id.toString(),
        userId: trade.userId.toString()
      }))
    });

  } catch (error) {
    console.error('Error checking trade results:', error);
    return NextResponse.json(
      { message: 'Internal server error' },
      { status: 500 }
    );
  }
}
