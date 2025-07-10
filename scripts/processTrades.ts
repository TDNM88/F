import mongoose from 'mongoose';
import { getMongoDb } from '../src/lib/db.js';
import TradingSession from '../src/models/TradingSession.js';
import Trade from '../src/models/Trade.js';

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

// Xử lý kết quả giao dịch
async function processTrades() {
  try {
    await connectDB();
    
    // Tìm các phiên đã kết thúc nhưng chưa được xử lý
    const now = new Date();
    const tenSecondsAgo = new Date(now.getTime() - 10000); // 10 giây trước
    
    const sessionsToProcess = await TradingSession.find({
      endTime: { $lte: tenSecondsAgo },
      status: 'PENDING'
    }).sort({ endTime: 1 });
    
    console.log(`Tìm thấy ${sessionsToProcess.length} phiên cần xử lý`);
    
    for (const session of sessionsToProcess) {
      console.log(`Đang xử lý phiên ${session.sessionId}...`);
      
      // Tìm tất cả các lệnh trong phiên này
      const trades = await Trade.find({ 
        sessionId: session.sessionId,
        status: 'PENDING'
      });
      
      console.log(`Có ${trades.length} lệnh cần xử lý`);
      
      // Cập nhật kết quả cho từng lệnh
      for (const trade of trades) {
        const isWin = trade.direction === session.result;
        const profit = isWin ? trade.amount * 1.8 : 0; // Tỷ lệ thắng 1.8 lần
        
        await Trade.updateOne(
          { _id: trade._id },
          { 
            status: isWin ? 'WIN' : 'LOSE',
            result: isWin ? 'WIN' : 'LOSE',
            profit,
            updatedAt: new Date()
          }
        );
        
        // Cập nhật số dư người dùng nếu thắng
        if (isWin) {
          // Ở đây cần thêm logic cập nhật số dư cho người dùng
          // Ví dụ: await User.updateOne({ _id: trade.userId }, { $inc: { balance: profit } });
        }
      }
      
      // Đánh dấu phiên đã xử lý xong
      await TradingSession.updateOne(
        { _id: session._id },
        { 
          status: 'COMPLETED',
          updatedAt: new Date()
        }
      );
      
      console.log(`✅ Đã xử lý xong phiên ${session.sessionId}`);
    }
    
    console.log('✅ Đã xử lý xong tất cả các phiên');
    process.exit(0);
  } catch (error) {
    console.error('❌ Lỗi khi xử lý giao dịch:', error);
    process.exit(1);
  }
}

// Chạy script
processTrades();
