// Load environment variables
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({
  path: path.resolve(__dirname, '../.env.local'),
  override: true
});

console.log('MONGODB_URI:', process.env.MONGODB_URI ? 'Đã cấu hình' : 'Chưa cấu hình');

// Import the seed function
const { default: seed } = await import('./seedTradingSessions.js');

// Run the seed function
seed().catch(error => {
  console.error('Lỗi khi chạy seed:', error);
  process.exit(1);
});
