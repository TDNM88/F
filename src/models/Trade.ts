import mongoose, { Document, Schema } from 'mongoose';

export interface ITrade extends Document {
  sessionId: string;
  userId: string;
  direction: 'UP' | 'DOWN';
  amount: number;
  status: 'PENDING' | 'WIN' | 'LOSE';
  result?: 'WIN' | 'LOSE';
  profit?: number;
  createdAt: Date;
  updatedAt: Date;
}

const tradeSchema = new Schema<ITrade>({
  sessionId: { type: String, required: true, index: true },
  userId: { type: String, required: true, index: true },
  direction: { type: String, enum: ['UP', 'DOWN'], required: true },
  amount: { type: Number, required: true },
  status: { 
    type: String, 
    enum: ['PENDING', 'WIN', 'LOSE'], 
    default: 'PENDING' 
  },
  result: { 
    type: String, 
    enum: ['WIN', 'LOSE'],
    required: false
  },
  profit: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Tạo index cho các trường thường xuyên được query
tradeSchema.index({ sessionId: 1, userId: 1 });

export default mongoose.models.Trade || mongoose.model<ITrade>('Trade', tradeSchema);
