// Load biến môi trường từ file .env.local
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import path from 'path';

// Lấy đường dẫn thư mục hiện tại
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load biến môi trường
dotenv.config({
  path: path.resolve(__dirname, '../.env.local'),
  override: true
});

// Log để kiểm tra
console.log('MONGODB_URI:', process.env.MONGODB_URI ? 'Đã cấu hình' : 'Chưa cấu hình');
console.log('Đường dẫn .env:', path.resolve(__dirname, '../.env.local'));

// Chạy script seed
try {
  const { default: seed } = await import('./seedTradingSessions.js');
  await seed();
} catch (error) {
  console.error('Lỗi khi chạy seed:', error);
  process.exit(1);
}
