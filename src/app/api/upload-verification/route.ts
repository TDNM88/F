import { NextRequest, NextResponse } from 'next/server';
import { verifyToken } from '@/lib/auth';
import { ObjectId } from 'mongodb';
import clientPromise from '@/lib/mongodb';
import { put } from '@vercel/blob';

// Maximum file size: 5MB
const MAX_FILE_SIZE = 5 * 1024 * 1024;

// Allowed file types
const ALLOWED_FILE_TYPES = ['image/jpeg', 'image/png', 'image/jpg'];

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

    const formData = await req.formData();
    const file = formData.get('file') as File;
    const type = formData.get('type') as 'front' | 'back';

    if (!file || !type) {
      return NextResponse.json(
        { message: 'Thiếu file hoặc loại file' },
        { status: 400 }
      );
    }

    // Verify file type
    if (!ALLOWED_FILE_TYPES.includes(file.type)) {
      return NextResponse.json(
        { message: 'Chỉ chấp nhận file ảnh định dạng JPG hoặc PNG' },
        { status: 400 }
      );
    }

    // Verify file size
    if (file.size > MAX_FILE_SIZE) {
      return NextResponse.json(
        { message: 'Kích thước file tối đa là 5MB' },
        { status: 400 }
      );
    }

    // Generate a unique filename
    const fileExt = file.name.split('.').pop();
    const fileName = `${user.userId}-${type}-${Date.now()}.${fileExt}`;
    const pathname = `verification/${fileName}`;

    // Upload to Vercel Blob
    const blob = await put(pathname, file, {
      access: 'public', // Vercel Blob only supports 'public' access
      addRandomSuffix: false,
    });

    // Update user document in MongoDB
    const client = await clientPromise;
    const db = client.db();
    
    const updateField = type === 'front' ? 'verification.cccdFront' : 'verification.cccdBack';
    
    await db.collection('users').updateOne(
      { _id: new ObjectId(user.userId) },
      { 
        $set: { 
          [updateField]: blob.url,
          'verification.verified': false,
          'verification.status': 'pending',
          'verification.submittedAt': new Date()
        },
        $setOnInsert: {
          createdAt: new Date()
        }
      },
      { upsert: true }
    );

    return NextResponse.json({ 
      success: true, 
      message: 'Tải lên thành công',
      url: blob.url
    });

  } catch (error) {
    console.error('Upload error:', error);
    return NextResponse.json(
      { message: error instanceof Error ? error.message : 'Lỗi khi tải lên' },
      { status: 500 }
    );
  }
}
