// Script tạo tài khoản admin
const { MongoClient } = require('mongodb');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const path = require('path');
const fs = require('fs');

// Load biến môi trường từ .env
const envPath = path.resolve(__dirname, '../.env.local');
if (fs.existsSync(envPath)) {
  dotenv.config({ path: envPath });
} else {
  dotenv.config();
}

// Thông tin kết nối MongoDB
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://ssi:hanoi12345@tradingcluster.edufyno.mongodb.net/?retryWrites=true&w=majority&appName=TradingCluster';

console.log('Sử dụng kết nối MongoDB:', MONGODB_URI);

// Thông tin tài khoản admin mới
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = 'admin123';

async function hashPassword(password) {
  const saltRounds = 10;
  return bcrypt.hash(password, saltRounds);
}

async function createAdmin() {
  try {
    console.log('Đang kết nối đến MongoDB...');
    // Sử dụng options được hỗ trợ bởi phiên bản MongoDB mới nhất
    const client = new MongoClient(MONGODB_URI);
    await client.connect();
    
    console.log('Kết nối thành công!');
    // Lấy database "test" (default) hoặc cái định nghĩa trong URI
    const db = client.db();
    
    // Kiểm tra xem tài khoản admin đã tồn tại chưa
    const existingAdmin = await db.collection('users').findOne({ username: ADMIN_USERNAME });
    if (existingAdmin) {
      console.log('Tài khoản admin đã tồn tại. Cập nhật quyền admin...');
      await db.collection('users').updateOne(
        { username: ADMIN_USERNAME },
        { $set: { role: 'admin' } }
      );
      console.log('Đã cập nhật quyền admin cho tài khoản hiện có.');
    } else {
      // Tạo tài khoản admin mới
      console.log('Đang tạo tài khoản admin mới...');
      const hashedPassword = await hashPassword(ADMIN_PASSWORD);
      
      // Thông tin người dùng admin
      const adminUser = {
        username: ADMIN_USERNAME,
        password: hashedPassword,
        fullName: 'Administrator',
        phone: '',
        role: 'admin',
        balance: { available: 0, frozen: 0 },
        createdAt: new Date(),
        updatedAt: new Date()
      };
      
      // Lưu vào cơ sở dữ liệu
      const result = await db.collection('users').insertOne(adminUser);
      console.log(`Tạo tài khoản admin thành công với ID: ${result.insertedId}`);
    }
    
    // Đóng kết nối
    await client.close();
    console.log('Hoàn tất!');
  } catch (error) {
    console.error('Lỗi:', error);
  }
}

// Thực thi hàm tạo admin
createAdmin().catch(console.error);
