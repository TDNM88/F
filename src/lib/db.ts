import mongoose from 'mongoose';

// Define interface for the cached MongoDB connection
interface MongooseCache {
  conn: typeof mongoose | null;
  promise: Promise<typeof mongoose> | null;
}

// Define types for global mongoose cache
declare global {
  var mongoose: MongooseCache | undefined;
}

const MONGODB_URI = process.env.MONGODB_URI;

// Log để debug
console.log('Đang kiểm tra MONGODB_URI:', {
  MONGODB_URI: MONGODB_URI ? 'Đã cấu hình' : 'Chưa cấu hình',
  NODE_ENV: process.env.NODE_ENV,
  CWD: process.cwd()
});

if (!MONGODB_URI) {
  console.error('Lỗi: MONGODB_URI chưa được cấu hình trong file .env.local');
  process.exit(1);
}

const MONGODB_DB = process.env.MONGODB_DB || 'trading';

// Initialize the cached variable with proper typing
let cached: MongooseCache = global.mongoose || { conn: null, promise: null };

// Set the global mongoose object if it doesn't exist
if (!global.mongoose) {
  global.mongoose = cached;
}

export async function connectToDatabase() {
  console.log('Đang thiết lập kết nối tới MongoDB Atlas...');
  
  if (cached.conn) {
    console.log('Sử dụng kết nối database đã được cache');
    return cached.conn;
  }

  if (!cached.promise) {
    console.log('Tạo kết nối mới tới MongoDB...');
    
    if (!MONGODB_URI) {
      throw new Error('MONGODB_URI không được định nghĩa');
    }

    const opts: mongoose.ConnectOptions = {
      bufferCommands: false,
      serverSelectionTimeoutMS: 10000, // Tăng timeout lên 10 giây
      socketTimeoutMS: 45000,
      retryWrites: true,
      w: 'majority',
      appName: 'TradingApp',
    };

    console.log(`Kết nối tới MongoDB với URI: ${MONGODB_URI.split('@')[1]?.split('?')[0] || MONGODB_URI}`);

    cached.promise = mongoose.connect(MONGODB_URI, opts)
      .then((mongoose) => {
        console.log('✅ Đã kết nối thành công tới MongoDB Atlas');
        return mongoose;
      })
      .catch((error) => {
        console.error('❌ Lỗi kết nối MongoDB:', error.message);
        throw error;
      });
  }

  try {
    console.log('Waiting for database connection...');
    cached.conn = await cached.promise;
    console.log('Database connection established');
  } catch (e) {
    console.error('Failed to connect to MongoDB:', e);
    cached.promise = null;
    throw e;
  }

  return cached.conn;
}

/**
 * Hàm trợ giúp để lấy MongoDB client connection từ mongoose
 * Sử dụng trong các API route để truy cập collection
 */
export async function getMongoDb() {
  try {
    console.log('🔄 Đang lấy kết nối MongoDB...');
    
    if (!MONGODB_URI) {
      throw new Error('MONGODB_URI chưa được cấu hình');
    }
    
    await connectToDatabase();
    
    if (!mongoose.connection.db) {
      throw new Error('Không thể thiết lập kết nối MongoDB');
    }
    
    console.log('✅ Đã kết nối thành công tới database:', mongoose.connection.db.databaseName);
    return mongoose.connection.db;
  } catch (error) {
    console.error('❌ Lỗi khi kết nối MongoDB:', error instanceof Error ? error.message : 'Unknown error');
    throw new Error('Không thể kết nối tới cơ sở dữ liệu. Vui lòng thử lại sau.');
  }
}
