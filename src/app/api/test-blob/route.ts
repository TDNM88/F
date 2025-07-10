import { put } from '@vercel/blob';
import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  try {
    // Tạo một file test đơn giản
    const { url } = await put('test-file.txt', 'Đây là file test cho Vercel Blob', {
      access: 'public',
      token: process.env.tdnm9988_READ_WRITE_TOKEN || process.env.BLOB_READ_WRITE_TOKEN, // Sử dụng biến môi trường tùy chỉnh
    });

    return NextResponse.json({ success: true, url });
  } catch (error) {
    console.error('Lỗi khi test Vercel Blob:', error);
    return NextResponse.json(
      { error: 'Lỗi khi test Vercel Blob', details: (error as Error).message },
      { status: 500 }
    );
  }
}
