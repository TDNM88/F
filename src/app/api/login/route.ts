import { NextResponse } from "next/server"
import { getMongoDb } from "@/lib/db"
import { comparePassword, generateToken } from "@/lib/auth"
import mongoose from 'mongoose';

export async function POST(request: Request) {
  try {
    let requestBody;
    try {
      requestBody = await request.json();
    } catch (parseError) {
      console.error('Error parsing request body:', parseError);
      return NextResponse.json(
        { success: false, message: "Lỗi định dạng dữ liệu" },
        { status: 400 }
      );
    }

    const { username, password } = requestBody;

    if (!username || !password) {
      console.log('Missing username or password');
      return NextResponse.json(
        { success: false, message: "Vui lòng nhập đủ thông tin" },
        { status: 400 }
      );
    }

    let db;
    // Test MongoDB connection
    console.log('Testing MongoDB connection...');
    try {
      db = await getMongoDb();
      if (!db) {
        console.error('MongoDB connection failed: db is null');
        throw new Error("Không thể kết nối cơ sở dữ liệu");
      }
      
      // Test the connection by listing collections
      const collections = await db.listCollections().toArray();
      console.log('Available collections:', collections.map((c: { name: string }) => c.name));
      
      // Check if users collection exists
      const usersCollection = collections.find((c: { name: string }) => c.name === 'users');
      if (!usersCollection) {
        console.error('Users collection not found');
        return NextResponse.json({ success: false, message: "Lỗi hệ thống: Users collection không tồn tại" }, { status: 500 });
      }
      
      console.log('MongoDB connection test successful');
    } catch (error: any) {
      console.error('MongoDB connection error:', error);
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      return NextResponse.json({ 
        success: false, 
        message: `Lỗi kết nối cơ sở dữ liệu: ${errorMessage}` 
      }, { status: 500 });
    }

    console.log('Attempting to find user:', username.trim().toLowerCase());
    
    // Find user with explicit projection to include only needed fields
    const user = await db.collection("users").findOne(
      { username: username.trim().toLowerCase() },
      { projection: { 
        _id: 1, 
        username: 1, 
        password: 1, 
        role: 1, 
        status: 1,
        balance: 1,
        bank: 1,
        verification: 1,
        createdAt: 1,
        lastLogin: 1
      }}
    );

    if (!user) {
      console.log('User not found');
      return NextResponse.json(
        { success: false, message: "Sai tài khoản hoặc mật khẩu" }, 
        { status: 401 }
      );
    }

    // Check if user is active
    if (user.status && user.status.active === false) {
      console.log('User account is not active:', user._id);
      return NextResponse.json(
        { success: false, message: "Tài khoản đã bị khóa" }, 
        { status: 401 }
      );
    }

    console.log('User found, comparing password...');
    console.log('Stored password hash:', user.password ? '***' : 'MISSING');
    
    if (!user.password) {
      console.error('No password hash found for user:', user._id);
      return NextResponse.json(
        { success: false, message: "Lỗi hệ thống: Mật khẩu không hợp lệ" },
        { status: 500 }
      );
    }

    let validPassword = false;
    try {
      console.log('Comparing password...');
      validPassword = await comparePassword(password, user.password);
      console.log('Password comparison result:', validPassword ? 'MATCH' : 'NO_MATCH');
    } catch (compareError) {
      console.error('Error comparing passwords:', compareError);
      return NextResponse.json(
        { success: false, message: "Lỗi xác thực mật khẩu" },
        { status: 500 }
      );
    }
    
    if (!validPassword) {
      console.log('Invalid password for user:', user._id);
      const responseData: any = { 
        success: false, 
        message: "Sai tài khoản hoặc mật khẩu"
      };
      
      // Add debug info in development
      if (process.env.NODE_ENV !== 'production') {
        responseData.debug = {
          userId: user._id,
          hasPassword: !!user.password,
          passwordLength: user.password?.length || 0
        };
      }
      
      return NextResponse.json(
        responseData,
        { status: 401 }
      );
    }
    
    console.log('Authentication successful for user:', user._id);

    // Update last login
    await db.collection("users").updateOne(
      { _id: user._id },
      {
        $set: {
          lastLogin: new Date(),
          updatedAt: new Date(),
        },
      },
    )

    // Generate token
    let token;
    try {
      token = generateToken(user._id.toString());
      console.log('Generated token for user:', user._id);
    } catch (tokenError) {
      console.error('Error generating token:', tokenError);
      return NextResponse.json(
        { success: false, message: "Lỗi tạo phiên đăng nhập" },
        { status: 500 }
      );
    }

    // Create response
    let response;
    try {
      const userResponse = {
        id: user._id.toString(),
        username: user.username,
        role: user.role || "user",
        balance: user.balance || { available: 0, frozen: 0 },
        // Include additional fields that might be needed by the client
        bank: user.bank,
        verification: user.verification,
        status: user.status,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin
      };
      
      console.log('Sending user data in login response:', JSON.stringify(userResponse, null, 2));
      
      response = NextResponse.json({
        success: true,
        user: userResponse,
        // Include debug info in development
        ...(process.env.NODE_ENV !== 'production' ? {
          _debug: {
            userId: user._id.toString(),
            hasToken: true,
            tokenStartsWith: token.substring(0, 10) + '...',
            userFields: Object.keys(userResponse)
          }
        } : {})
      });
    } catch (responseError) {
      console.error('Error creating response:', responseError);
      return NextResponse.json(
        { success: false, message: "Lỗi tạo phản hồi" },
        { status: 500 }
      );
    }

    try {
      // Set cookie with secure options
      const isProduction = process.env.NODE_ENV === 'production';
      const cookieOptions = {
        httpOnly: true,
        secure: isProduction,
        maxAge: 60 * 60 * 24 * 7, // 1 week
        path: '/',
        sameSite: 'lax' as const,
        domain: isProduction ? process.env.COOKIE_DOMAIN : 'localhost'
      };
      
      console.log('Cookie options:', JSON.stringify({
        ...cookieOptions,
        domain: cookieOptions.domain === 'localhost' ? 'localhost' : '***'
      }));
      
      // Set both token and auth_token cookies for compatibility
      response.cookies.set('auth_token', token, cookieOptions);
      response.cookies.set('token', token, cookieOptions);
      
      // Also set a response header for API clients
      response.headers.set('X-Auth-Token', token);
        
      // For debugging
      console.log('Login successful, token set:', token.substring(0, 15) + '...');
      console.log('Cookie options:', {
        ...cookieOptions,
        domain: cookieOptions.domain === 'localhost' ? 'localhost' : '***'
      });
      
      return response;
    } catch (cookieError) {
      console.error('Error setting cookie:', cookieError);
      // Still return the response even if cookie setting fails
      // The client can still get the token from the response body
      return response;
    }
  } catch (error) {
    console.error("Login error:", error);
    
    let errorMessage = "Lỗi hệ thống";
    let statusCode = 500;
    
    // Handle different types of errors
    if (error instanceof Error) {
      if (error.name === 'MongoServerError') {
        errorMessage = "Lỗi cơ sở dữ liệu";
      } else if (error.name === 'ValidationError') {
        errorMessage = "Dữ liệu không hợp lệ";
        statusCode = 400;
      }
      console.error(`Error details: ${error.name} - ${error.message}`);
      if (error.stack) {
        console.error(error.stack);
      }
    }
    
    return NextResponse.json(
      { 
        success: false, 
        message: errorMessage 
      }, 
      { status: statusCode }
    );
  }
}
