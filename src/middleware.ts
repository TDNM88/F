import { NextResponse, NextRequest } from 'next/server';

// Danh sách domain được phép truy cập
const allowedOrigins = [
  'https://inal-hsc1.com',
  'https://www.inal-hsc1.com',
  'https://london-hsc.com',
  'https://www.london-hsc.com',
  // Môi trường phát triển
  'http://localhost:3000',
  'http://127.0.0.1:3000',
];

// Các header bảo mật
const securityHeaders = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
} as const;

// Hàm thiết lập CORS headers
function setCorsHeaders(response: NextResponse, origin: string) {
  response.headers.set('Access-Control-Allow-Origin', origin);
  response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept');
  response.headers.set('Access-Control-Allow-Credentials', 'true');
  response.headers.set('Access-Control-Max-Age', '86400'); // 24 giờ
  response.headers.set('Vary', 'Origin');
  return response;
}

// Hàm lấy token từ request
function getTokenFromRequest(request: NextRequest): string | null {
  // Ưu tiên lấy từ header Authorization
  const authHeader = request.headers.get('authorization');
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.split(' ')[1];
  }
  
  // Kiểm tra cookie
  const cookie = request.cookies.get('token')?.value;
  if (cookie) return cookie;
  
  // Kiểm tra URL parameters (cho các trường hợp đặc biệt)
  const url = new URL(request.url);
  const tokenParam = url.searchParams.get('token');
  
  return tokenParam;
}

// Kiểm tra xem path có phải là public không
function isPublicPath(pathname: string): boolean {
  const publicPaths = [
    // Public pages
    '/',
    '/login',
    '/register',
    '/forgot-password',
    '/reset-password',
    
    // Public APIs
    '/api/auth',
    '/api/settings',
    '/api/public',
    
    // Static assets
    '/_next',
    '/favicon.ico',
    '/icons',
    '/images',
    '/fonts',
    
    // API endpoints that should be public
    '/api/*',

    // Development only
    ...(process.env.NODE_ENV === 'development' ? [
      '/api/__coverage__',
      '/__nextjs_original-stack-frame',
      '/_error',
      '/_webpack'
    ] : [])
  ];
  
  return publicPaths.some(path => 
    pathname === path || pathname.startsWith(`${path}/`)
  );
}

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const origin = request.headers.get('origin') || '';
  const isAllowedOrigin = allowedOrigins.includes(origin) ||
    (process.env.NODE_ENV === 'development' && origin.startsWith('http://localhost'));

  // Xử lý preflight request
  if (request.method === 'OPTIONS') {
    const response = new NextResponse(null, { status: 204 });
    return setCorsHeaders(response, origin);
  }

  // Tạo response mới với CORS headers nếu cần
  let response: NextResponse;
  
  if (isAllowedOrigin) {
    const newResponse = NextResponse.next();
    setCorsHeaders(newResponse, origin);
    response = newResponse;
  } else {
    response = NextResponse.next();
  }

  // Skip authentication check for public paths and static resources
  if (isPublicPath(pathname) || pathname.startsWith('/_next/') || pathname.startsWith('/static/') || pathname.startsWith('/public/') || pathname === '/favicon.ico') {
    return response;
  }

  // Get token from request
  const token = getTokenFromRequest(request);
  
  // For API routes, just pass through the request
  // API routes should handle their own authentication
  if (pathname.startsWith('/api')) {
    return response;
  }
  
  // If no token, redirect to login
  if (!token) {
    // Don't redirect if we're already going to login
    if (!pathname.startsWith('/login')) {
      const loginUrl = new URL('/login', request.url);
      loginUrl.searchParams.set('returnUrl', pathname);
      return NextResponse.redirect(loginUrl);
    }
    return response;
  }
  
  // Don't verify token for login page to prevent loops
  if (pathname.startsWith('/login') || pathname.startsWith('/auth/')) {
    return response;
  }
  
  // For other protected routes, verify the token
  try {
    const verifyResponse = await fetch(new URL('/api/auth/verify', request.url), {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
      },
      credentials: 'include'
    });
    
    if (!verifyResponse.ok) {
      // If token is invalid, clear it and redirect to login
      const loginUrl = new URL('/login', request.url);
      loginUrl.searchParams.set('returnUrl', pathname);
      loginUrl.searchParams.set('expired', 'true');
      
      // Clear the invalid token
      response.cookies.set('token', '', { 
        path: '/', 
        expires: new Date(0) 
      });
      
      return NextResponse.redirect(loginUrl);
    }
    
    // If we get here, token is valid - proceed with the request
    return response;
    
  } catch (error) {
    console.error('Token verification failed:', error);
    // On error, proceed with the request to avoid blocking the user
    return response;
  }

}

// Define paths that should be excluded from middleware processing
const excludedPaths = [
  // Static files
  '/_next/static',
  '/_next/image',
  '/static',
  
  // Public assets
  '/favicon.ico',
  '/favicon-*',
  '/apple-icon-*',
  '/android-chrome-*',
  '/safari-pinned-tab.svg',
  '/site.webmanifest',
  
  // Public API routes
  '/api/auth',
  '/api/public',
  
  // Development specific
  '/__nextjs_original-stack-frame',
  '/_error',
  '/_webpack',
  
  // Other static assets
  '/fonts',
  '/images',
  '/icons',
  
  // Public paths (already handled by isPublicPath)
  '/',
  '/home',
  '/about',
  '/contact',
  '/privacy-policy',
  '/terms-of-service',
  '/faq',
  '/help',
  
  // Auth related
  '/login',
  '/register',
  '/forgot-password',
  '/reset-password',
  '/verify-email',
  '/auth/reset-password',
  '/auth/verify-email',
  
  // Public API endpoints
  '/api/rates',
  '/api/markets',
  '/api/announcements',
  '/api/settings',
  '/api/config',
  '/api/health',
  '/api/version',
  
  // Public assets and resources
  '/images',
  '/assets',
  '/downloads',
  '/documents',
  
  // Public blog/content
  '/blog',
  '/news',
  '/articles',
  
  // Public product pages
  '/products',
  '/pricing',
  '/features',
  
  // Public support
  '/support',
  '/contact-us',
  '/help-center',
  
  // Error pages
  '/404',
  '/500',
  '/maintenance',
  
  // Public webhooks (if any)
  '/api/webhooks',
  
  // Public integrations
  '/api/integrations',
  
  // Public documentation
  '/docs',
  '/api-docs',
  
  // Public status page
  '/status',
  
  // Sitemap and robots
  '/sitemap.xml',
  '/robots.txt'
];
