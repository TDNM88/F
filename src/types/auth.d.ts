import { NextRequest } from 'next/server';

// Định nghĩa kiểu dữ liệu User
export interface User {
  _id: string;
  username: string;
  email: string;
  name: string;
  role: string;
  balance?: {
    available: number;
    frozen: number;
  };
  bank?: {
    name: string;
    accountNumber: string;
    accountHolder: string;
  };
  verification?: {
    verified: boolean;
    cccdFront: string;
    cccdBack: string;
  };
  status?: {
    active: boolean;
    betLocked?: boolean;
    withdrawLocked?: boolean;
  };
  createdAt?: string | Date;
  updatedAt?: string | Date;
  lastLogin?: string | Date;
}

// Mở rộng NextRequest để thêm thuộc tính user
declare module 'next/server' {
  interface NextRequest {
    user: User;
  }
}

// Xuất kiểu AuthRequest để sử dụng trong các file khác
export type AuthRequest = NextRequest;
