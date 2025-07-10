/**
 * Re-export AuthProvider và useAuth từ useAuthNew
 * Giúp các file hiện tại vẫn import từ useAuth.tsx hoạt động bình thường
 * mà không cần sửa tất cả imports trong codebase
 */
'use client';

import { useAuth, AuthProvider } from './useAuthNew';
import type { AuthContextType } from './useAuthNew';

export { useAuth, AuthProvider };
export type { AuthContextType };
