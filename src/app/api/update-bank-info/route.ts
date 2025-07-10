import { NextRequest, NextResponse } from 'next/server';
import { verifyToken } from '@/lib/auth';
import { ObjectId } from 'mongodb';
import clientPromise from '@/lib/mongodb';

export async function POST(req: NextRequest) {
  try {
    const token = req.headers.get('authorization')?.split(' ')[1];
    if (!token) {
      return NextResponse.json({ message: 'Bạn cần đăng nhập' }, { status: 401 });
    }

    const user = await verifyToken(token);
    if (!user) {
      return NextResponse.json({ message: 'Phiên đăng nhập hết hạn' }, { status: 401 });
    }

    const body = await req.json();
    const { accountHolder, bankType, bankName, accountNumber } = body;

    // Validate required fields
    if (!accountHolder || !bankType || !bankName || !accountNumber) {
      return NextResponse.json(
        { message: 'Vui lòng điền đầy đủ thông tin' },
        { status: 400 }
      );
    }

    // Update user document in MongoDB
    const client = await clientPromise;
    const db = client.db();

    await db.collection('users').updateOne(
      { _id: new ObjectId(user.userId) },
      {
        $set: {
          'bankInfo.accountHolder': accountHolder,
          'bankInfo.bankType': bankType,
          'bankInfo.bankName': bankName,
          'bankInfo.accountNumber': accountNumber,
          'bankInfo.verified': false, // Reset verification status when bank info changes
          updatedAt: new Date()
        },
        $setOnInsert: {
          createdAt: new Date()
        }
      },
      { upsert: true }
    );

    return NextResponse.json({
      success: true,
      message: 'Cập nhật thông tin ngân hàng thành công',
      data: {
        accountHolder,
        bankType,
        bankName,
        accountNumber,
        verified: false
      }
    });
  } catch (error) {
    console.error('Update bank info error:', error);
    return NextResponse.json(
      { 
        success: false, 
        message: error instanceof Error ? error.message : 'Có lỗi xảy ra khi cập nhật thông tin ngân hàng' 
      },
      { status: 500 }
    );
  }
}
