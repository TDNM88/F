import { NextResponse } from 'next/server';
import { withAuth } from '@/middleware/auth';

// Using our new auth middleware
export const GET = withAuth(async (request) => {
  try {
    // User is already authenticated by the middleware
    const user = request.user;
    
    return NextResponse.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        role: user.role || 'user',
        balance: user.balance || { available: 0, frozen: 0 },
        bank: user.bank,
        verification: user.verification,
        status: user.status,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin,
      }
    });
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
