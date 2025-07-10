import { NextResponse } from "next/server"
import { getMongoDb } from "@/lib/db"
import { parseToken } from "@/lib/auth"
import { ObjectId } from "mongodb"

export async function GET(request: Request) {
  try {
    // Get token from cookie
    const cookies = request.headers.get("cookie") || ""
    console.log('Cookies:', cookies); // Debug log
    
    const tokenMatch = cookies.match(/token=([^;]+)/)
    console.log('Token match:', tokenMatch ? 'found' : 'not found'); // Debug log

    if (!tokenMatch) {
      console.log('No token found in cookies');
      return NextResponse.json({ success: false, message: "Chưa đăng nhập" }, { status: 401 })
    }

    const token = tokenMatch[1]
    console.log('Token found, length:', token.length); // Debug log
    
    const tokenData = parseToken(token)
    console.log('Parsed token data:', tokenData); // Debug log

    if (!tokenData) {
      console.log('Invalid token format');
      return NextResponse.json({ success: false, message: "Token không hợp lệ" }, { status: 401 })
    }

    // Check token expiry (7 days)
    const now = Date.now()
    const tokenAge = now - tokenData.timestamp
    const maxAge = 7 * 24 * 60 * 60 * 1000 // 7 days in milliseconds

    if (tokenAge > maxAge) {
      return NextResponse.json({ success: false, message: "Token đã hết hạn" }, { status: 401 })
    }

    // Get user from database
    const db = await getMongoDb()
    if (!db) {
      throw new Error("Không thể kết nối cơ sở dữ liệu")
    }

    console.log('Looking up user with ID:', tokenData.userId);
    
    try {
      // First get the user without any projection to see all available fields
      const userDoc = await db.collection("users").findOne(
        { _id: new ObjectId(tokenData.userId) }
      );
      
      if (!userDoc) {
        console.error('User not found in database');
        return NextResponse.json({ 
          success: false, 
          message: "Người dùng không tồn tại",
          _debug: process.env.NODE_ENV !== 'production' ? {
            userId: tokenData.userId,
            error: 'user_not_found'
          } : undefined
        }, { status: 404 });
      }
      
      // Create a new object with only the fields we want to return
      const userData = {
        _id: userDoc._id,
        username: userDoc.username,
        role: userDoc.role || 'user',
        balance: userDoc.balance || { available: 0, frozen: 0 },
        bank: userDoc.bank,
        verification: userDoc.verification,
        status: userDoc.status,
        createdAt: userDoc.createdAt,
        lastLogin: userDoc.lastLogin,
        // Add any other fields you want to include
      };
      
      console.log('Found user:', { 
        id: userData._id, 
        username: userData.username,
        role: userData.role 
      });
      
      // Check if user is still active
      if (userData.status && !userData.status.active) {
        console.log('User account is inactive');
        return NextResponse.json({ success: false, message: "Tài khoản đã bị khóa" }, { status: 401 });
      }
      
      console.log('User is active, proceeding with auth');

      const userResponse = {
        id: userData._id.toString(),
        username: userData.username,
        role: userData.role || "user",
        balance: userData.balance || { available: 0, frozen: 0 },
        bank: userData.bank || { name: "", accountNumber: "", accountHolder: "" },
        verification: userData.verification || { verified: false, cccdFront: "", cccdBack: "" },
        status: userData.status || { active: true, betLocked: false, withdrawLocked: false },
        createdAt: userData.createdAt,
        lastLogin: userData.lastLogin,
      }

      return NextResponse.json({
        success: true,
        user: userResponse,
      })
    } catch (dbError) {
      console.error('Database error in /api/auth/me:', dbError);
      return NextResponse.json({ 
        success: false, 
        message: "Lỗi cơ sở dữ liệu",
        _debug: process.env.NODE_ENV !== 'production' ? {
          error: 'database_error',
          message: dbError instanceof Error ? dbError.message : String(dbError)
        } : undefined
      }, { status: 500 });
    }
  } catch (error) {
    console.error("Auth me error:", error)
    return NextResponse.json({ success: false, message: "Lỗi hệ thống" }, { status: 500 })
  }
}
