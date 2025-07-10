import mongoose, { Document, Schema } from 'mongoose';

export interface ITradingSession extends Document {
  sessionId: string;
  startTime: Date;
  endTime: Date;
  result?: 'UP' | 'DOWN';
  status: 'PENDING' | 'COMPLETED';
  createdAt: Date;
  updatedAt: Date;
}

const tradingSessionSchema = new Schema<ITradingSession>({
  sessionId: { 
    type: String, 
    required: true, 
    unique: true,
    index: true 
  },
  startTime: { 
    type: Date, 
    required: true,
    index: true 
  },
  endTime: { 
    type: Date, 
    required: true,
    index: true 
  },
  result: { 
    type: String, 
    enum: ['UP', 'DOWN'],
    required: false
  },
  status: { 
    type: String, 
    enum: ['PENDING', 'COMPLETED'], 
    default: 'PENDING',
    index: true 
  },
  createdAt: { 
    type: Date, 
    default: Date.now,
    index: true 
  },
  updatedAt: { 
    type: Date, 
    default: Date.now 
  }
});

// Tạo index cho các trường thường xuyên được query
tradingSessionSchema.index({ status: 1, endTime: 1 });

export default mongoose.models.TradingSession || 
  mongoose.model<ITradingSession>('TradingSession', tradingSessionSchema);
