import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

// Lấy đường dẫn thư mục hiện tại
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load biến môi trường từ file .env.local
dotenv.config({
  path: path.resolve(__dirname, '../.env.local'),
  override: true
});

// Log để kiểm tra
console.log('Đã load biến môi trường từ .env.local');
console.log('MONGODB_URI:', process.env.MONGODB_URI ? 'Đã cấu hình' : 'Chưa cấu hình');
