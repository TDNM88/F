import { handleUpload, type HandleUploadBody } from '@vercel/blob/client';
import { NextResponse } from 'next/server';
import { verifyToken } from '@/lib/auth';

export async function POST(request: Request): Promise<NextResponse> {
  try {
    // Kiểm tra xác thực người dùng
    const authHeader = request.headers.get('authorization');
    const token = authHeader?.split(' ')[1];
    
    if (!token) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    
    const user = await verifyToken(token);
    if (!user || !user.id) {
      return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
    }

    const body = (await request.json()) as HandleUploadBody;
    
    // Xử lý việc upload thông qua Vercel Blob
    const jsonResponse = await handleUpload({
      body,
      request,
      onBeforeGenerateToken: async ({ pathname, clientPayload }) => {
        // Thêm prefix cho tên file để phân loại theo user
        return { 
          tokenPayload: {
            userId: user.id,
            // Có thể thêm các metadata khác ở đây
            timestamp: Date.now(),
          } 
        };
      },
      onUploadCompleted: async ({ blob, tokenPayload }) => {
        // Có thể lưu thông tin vào database ở đây
        console.log('Upload completed', blob.url, tokenPayload);
      },
    });

    return NextResponse.json(jsonResponse);
  } catch (error) {
    return NextResponse.json(
      { error: 'Internal Server Error' },
      { status: 500 }
    );
  }
}
