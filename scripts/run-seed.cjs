// Load environment variables
require('dotenv').config({ path: '.env.local' });

console.log('MONGODB_URI:', process.env.MONGODB_URI ? 'Đã cấu hình' : 'Chưa cấu hình');

// Run the seed script
require('tsx').register();
require('./seedTradingSessions.ts');
