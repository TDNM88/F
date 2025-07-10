// scripts/seedTradingSessions.mjs
import 'dotenv/config';  // Sử dụng import thay vì require
import mongoose from 'mongoose';
import { getMongoDb } from '../src/lib/db.js';
import TradingSession from '../src/models/TradingSession.js';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Kết nối tới database
async function connectDB() {
  try {
    await getMongoDb();
    console.log('✅ Đã kết nối tới MongoDB');
  } catch (error) {
    console.error('❌ Lỗi kết nối MongoDB:', error);
    process.exit(1);
  }
}

// Hàm chính
async function seedTradingSessions() {
  try {
    await connectDB();
    
    // Xóa dữ liệu cũ nếu cần
    console.log('🔄 Đang xóa dữ liệu cũ...');
    await TradingSession.deleteMany({});
    
    const now = new Date();
    const sessions = [];
    
    console.log('🔄 Đang tạo dữ liệu mẫu...');
    
    // Tạo 60 phiên giao dịch trong 60 phút gần nhất
    for (let i = 0; i < 60; i++) {
      const startTime = new Date(now.getTime() - (60 - i) * 60 * 1000);
      const endTime = new Date(startTime.getTime() + 60 * 1000);
      
      // Tạo sessionId theo định dạng YYMMDDHHmm
      const year = startTime.getFullYear().toString().slice(-2);
      const month = (startTime.getMonth() + 1).toString().padStart(2, '0');
      const day = startTime.getDate().toString().padStart(2, '0');
      const hours = startTime.getHours().toString().padStart(2, '0');
      const minutes = startTime.getMinutes().toString().padStart(2, '0');
      const sessionId = `${year}${month}${day}${hours}${minutes}`;
      
      // Tỷ lệ thắng 50%
      const result = Math.random() > 0.5 ? 'UP' : 'DOWN';
      
      sessions.push({
        sessionId,
        startTime,
        endTime,
        result,
        status: 'COMPLETED',
        createdAt: new Date(),
        updatedAt: new Date()
      });
    }
    
    // Thêm vào database
    console.log('🔄 Đang lưu vào database...');
    await TradingSession.insertMany(sessions);
    console.log(`✅ Đã thêm thành công ${sessions.length} phiên giao dịch`);
    
    // Đóng kết nối
    await mongoose.connection.close();
    console.log('✅ Đã đóng kết nối MongoDB');
    
    return sessions;
  } catch (error) {
    console.error('❌ Lỗi khi thêm dữ liệu mẫu:', error);
    throw error;
  }
}

// Chạy script
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  seedTradingSessions().catch(console.error);
}