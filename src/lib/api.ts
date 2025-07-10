import { getAuthSession } from './simple-auth';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || '';

export async function fetchWithAuth(
  input: RequestInfo | URL,
  init?: RequestInit
): Promise<Response> {
  const { token } = getAuthSession();
  
  const headers = new Headers(init?.headers);
  
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  
  // Ensure JSON content type for requests with body
  if (init?.body && !(init.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }

  // Handle relative and absolute URLs
  const url = typeof input === 'string' && input.startsWith('http')
    ? input
    : `${API_BASE_URL}${input}`;
  
  const response = await fetch(url, {
    ...init,
    headers,
    credentials: 'include', // Include cookies for cross-origin requests
  });
  
  // Handle 401 Unauthorized
  if (response.status === 401) {
    // Clear invalid session
    if (typeof window !== 'undefined') {
      const { clearAuthSession } = await import('./simple-auth');
      clearAuthSession();
      window.location.href = '/login';
    }
    throw new Error('Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại.');
  }
  
  return response;
}

export async function fetchJsonWithAuth<T>(
  input: RequestInfo | URL,
  init?: RequestInit
): Promise<T> {
  const response = await fetchWithAuth(input, init);
  return response.json();
}
