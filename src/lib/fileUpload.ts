import { put } from '@vercel/blob';

/**
 * Utility để upload file sử dụng Vercel Blob Storage
 * File được lưu với tên duy nhất và trả về URL để truy cập file
 */
export async function uploadFile(file: File): Promise<string> {
  try {
    // Tạo tên file duy nhất để tránh trùng lặp
    const uniqueFilename = `${Date.now()}-${file.name.replace(/[^a-zA-Z0-9.]/g, '_')}`;
    
    // Upload file lên Vercel Blob Storage với biến môi trường tùy chỉnh
    const { url } = await put(uniqueFilename, file, {
      access: 'public', // Công khai để có thể truy cập URL mà không cần xác thực
      contentType: file.type || 'application/octet-stream',
      cacheControlMaxAge: 31536000, // Cache 1 năm (60 * 60 * 24 * 365)
      token: process.env.tdnm9988_READ_WRITE_TOKEN || process.env.BLOB_READ_WRITE_TOKEN, // Sử dụng biến môi trường tùy chỉnh
    });
    
    // Trả về URL công khai để truy cập file
    return url;
  } catch (error) {
    console.error('Error uploading file to Vercel Blob:', error);
    throw new Error('Không thể upload file');
  }
}
