import mongoose, { Document, Schema, Model } from 'mongoose';

// Định nghĩa interface cho document User
export interface IUser extends Document {
  username: string;
  password: string;
  fullName: string;
  role: 'admin' | 'user';
  balance: {
    available: number;
    frozen: number;
  };
  bank: {
    name: string;
    accountNumber: string;
    accountHolder: string;
  };
  verification: {
    verified: boolean;
    cccdFront: string;
    cccdBack: string;
  };
  status: {
    active: boolean;
    betLocked: boolean;
    withdrawLocked: boolean;
  };
  loginInfo: string;
  lastLogin?: Date;
  createdAt: Date;
  updatedAt: Date;
}

// Định nghĩa schema cho User
const userSchema = new Schema<IUser>({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  fullName: { type: String, default: '' },
  role: { type: String, enum: ['admin', 'user'], default: 'user' },
  balance: {
    available: { type: Number, default: 0 },
    frozen: { type: Number, default: 0 },
  },
  bank: {
    name: { type: String, default: '' },
    accountNumber: { type: String, default: '' },
    accountHolder: { type: String, default: '' },
  },
  verification: {
    verified: { type: Boolean, default: false },
    cccdFront: { type: String, default: '' },
    cccdBack: { type: String, default: '' },
  },
  status: {
    active: { type: Boolean, default: true },
    betLocked: { type: Boolean, default: false },
    withdrawLocked: { type: Boolean, default: false },
  },
  loginInfo: { type: String, default: '' },
  lastLogin: { type: Date },
  createdAt: { type: Date, default: Date.now },
}, {
  timestamps: true,
});

// Kiểm tra xem model đã tồn tại chưa để tránh lỗi khi hot reload
let UserModel: Model<IUser>;
try {
  // Nếu model đã tồn tại, sử dụng lại
  UserModel = mongoose.model<IUser>('User');
} catch {
  // Nếu chưa có model, tạo mới
  UserModel = mongoose.model<IUser>('User', userSchema);
}

export default UserModel;
