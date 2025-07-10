/**
 * Re-export AuthProvider và useAuth từ useAuthNew
 * Giúp các file hiện tại vẫn import từ useAuth.tsx hoạt động bình thường
 * mà không cần sửa tất cả imports trong codebase
 */

export { useAuth, AuthProvider, AuthContextType } from './useAuthNew';
