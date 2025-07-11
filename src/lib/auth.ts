import { NextRequest, NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { cookies } from 'next/headers';
import { ReadonlyRequestCookies } from 'next/dist/server/web/spec-extension/adapters/request-cookies';

// Constants
const JWT_SECRET = process.env.JWT_SECRET || 'your-default-secret-key-change-in-production';
export const TOKEN_MAX_AGE_SEC = 60 * 60 * 24 * 7; // 7 days

/**
 * Hàm so sánh mật khẩu đầu vào với mật khẩu đã được hash
 * @param plainPassword Mật khẩu đầu vào
 * @param hashedPassword Mật khẩu đã được hash trong database
 * @returns Promise<boolean> True nếu mật khẩu khớp, false nếu không khớp
 */
export async function comparePassword(plainPassword: string, hashedPassword: string): Promise<boolean> {
  try {
    return await bcrypt.compare(plainPassword, hashedPassword);
  } catch (error) {
    console.error('Error comparing passwords:', error);
    return false;
  }
}

/**
 * Hàm hash mật khẩu
 * @param password Mật khẩu cần hash
 * @returns Promise<string> Mật khẩu đã được hash
 */
export async function hashPassword(password: string): Promise<string> {
  const saltRounds = 10;
  return await bcrypt.hash(password, saltRounds);
}

/**
 * Tạo JWT token cho người dùng
 * @param userId ID của người dùng
 * @returns string JWT token
 */
export function generateToken(userId: string): string {
  return jwt.sign(
    { sub: userId },
    JWT_SECRET,
    { expiresIn: TOKEN_MAX_AGE_SEC }
  );
}

/**
 * Xác thực JWT token
 * @param token JWT token cần xác thực
 * @returns any Payload của token nếu hợp lệ, null nếu không hợp lệ
 */
export function verifyToken(token: string): any {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    console.error('Token verification failed:', error);
    return null;
  }
}

/**
 * Lấy token từ request (từ header Authorization hoặc cookie)
 * @param req NextRequest object
 * @returns string | null Token nếu tồn tại, null nếu không tìm thấy
 */
export function getTokenFromRequest(req: NextRequest): string | null {
  // Thử lấy từ Authorization header
  const authHeader = req.headers.get('Authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }
  
  // Thử lấy từ cookie - chỉ sử dụng req.cookies thay vì cookies() API
  const token = req.cookies.get('token')?.value;
  return token || null;
}

/**
 * Middleware để xác thực người dùng
 * @param req NextRequest object
 * @returns NextResponse | null NextResponse nếu xác thực thất bại, null nếu xác thực thành công
 */
export function withAuth(req: NextRequest) {
  const token = getTokenFromRequest(req);
  
  if (!token) {
    return NextResponse.json(
      { success: false, message: 'Unauthorized - No token provided' },
      { status: 401 }
    );
  }
  
  const payload = verifyToken(token);
  if (!payload) {
    return NextResponse.json(
      { success: false, message: 'Unauthorized - Invalid token' },
      { status: 401 }
    );
  }
  
  // Xác thực thành công
  return null;
}
