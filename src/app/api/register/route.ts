import { NextResponse } from "next/server"
import { getMongoDb } from "@/lib/db"
import { hashPassword } from "@/lib/auth"

export async function POST(request: Request) {
  try {
    const { username, password } = await request.json()

    // Validate input
    if (!username || !password) {
      return NextResponse.json({ success: false, message: "Vui lòng nhập đầy đủ thông tin" }, { status: 400 })
    }

    // Validate username format
    if (username.length < 3) {
      return NextResponse.json({ success: false, message: "Tên đăng nhập phải có ít nhất 3 ký tự" }, { status: 400 })
    }

    // Validate password length
    if (password.length < 6) {
      return NextResponse.json({ success: false, message: "Mật khẩu phải có ít nhất 6 ký tự" }, { status: 400 })
    }

    const db = await getMongoDb()
    if (!db) {
      throw new Error("Không thể kết nối cơ sở dữ liệu")
    }

    // Check if username already exists
    const existingUser = await db.collection("users").findOne({
      username: username.trim().toLowerCase(),
    })

    if (existingUser) {
      return NextResponse.json({ success: false, message: "Tên đăng nhập đã được sử dụng" }, { status: 400 })
    }

    // Hash password
    const hashedPassword = await hashPassword(password)

    // Create new user
    const now = new Date()
    const result = await db.collection("users").insertOne({
      username: username.trim().toLowerCase(),
      password: hashedPassword,
      role: "user",
      balance: {
        available: 0,
        frozen: 0,
      },
      bank: {
        name: "",
        accountNumber: "",
        accountHolder: "",
      },
      verification: {
        verified: false,
        cccdFront: "",
        cccdBack: "",
      },
      status: {
        active: true,
        betLocked: false,
        withdrawLocked: false,
      },
      loginInfo: "",
      createdAt: now,
      updatedAt: now,
    })

    if (!result.insertedId) {
      throw new Error("Không thể tạo tài khoản")
    }

    return NextResponse.json({
      success: true,
      message: "Đăng ký thành công!",
      userId: result.insertedId.toString(),
    })
  } catch (error) {
    console.error("Lỗi đăng ký:", error)
    return NextResponse.json({ success: false, message: "Lỗi hệ thống" }, { status: 500 })
  }
}
