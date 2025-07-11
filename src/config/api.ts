const getApiBaseUrl = () => {
  if (typeof window === 'undefined') {
    // Phía server
    return `https://${process.env.NEXT_PUBLIC_DEFAULT_DOMAIN}:${process.env.NEXT_PUBLIC_API_PORT}`;
  }

  // Phía client
  const currentDomain = window.location.hostname;
  const isAlternateDomain = currentDomain === process.env.NEXT_PUBLIC_ALTERNATE_DOMAIN;
  
  return isAlternateDomain 
    ? `https://${process.env.NEXT_PUBLIC_ALTERNATE_DOMAIN}:${process.env.NEXT_PUBLIC_API_PORT}`
    : `https://${process.env.NEXT_PUBLIC_DEFAULT_DOMAIN}:${process.env.NEXT_PUBLIC_API_PORT}`;
};

export const API_CONFIG = {
  BASE_URL: getApiBaseUrl(),
  ENDPOINTS: {
    // Authentication
    AUTH: {
      LOGIN: '/auth/login',
      LOGOUT: '/auth/logout',
      ME: '/auth/me',
      REGISTER: '/register',
      SETUP: '/setup',
    },
    
    // Users
    USERS: {
      BASE: '/users',
      BANK_INFO: '/users/bank-info',
      UPDATE_BANK_INFO: '/users/bank-info',
    },
    
    // Trades
    TRADES: {
      BASE: '/trades',
      PLACE: '/trades/place',
      CHECK_RESULTS: '/trades/check-results',
      BY_ID: (id: string) => `/trades/${id}`,
    },
    
    // Orders
    ORDERS: {
      BASE: '/orders',
      HISTORY: '/orders/history',
    },
    
    // Sessions
    SESSIONS: {
      CURRENT: '/sessions/current',
      BASE: '/sessions',
    },
    
    // Deposits
    DEPOSITS: {
      BASE: '/deposits',
      HISTORY: '/deposits/history',
    },
    
    // Withdrawals
    WITHDRAWALS: {
      BASE: '/withdrawals',
      HISTORY: '/withdrawals/history',
    },
    
    // Admin
    ADMIN: {
      // Users
      USERS: {
        BASE: '/admin/users',
        BY_ID: (id: string) => `/admin/users/${id}`,
      },
      
      // Deposits
      DEPOSITS: {
        BASE: '/admin/deposits',
        BY_ID: (id: string) => `/admin/deposits/${id}`,
      },
      
      // Withdrawals
      WITHDRAWALS: {
        BASE: '/admin/withdrawals',
        BY_ID: (id: string) => `/admin/withdrawals/${id}`,
      },
      
      // Verification
      VERIFICATION: {
        REQUESTS: '/admin/verification-requests',
        BY_ID: (id: string) => `/admin/verification-requests/${id}`,
      },
            
      // Stats
      STATS: {
        BASE: '/admin/stats',
      },
    },
    
    // Upload
    UPLOAD: {
      BASE: '/upload',
      BLOB: '/blob',
      TEST_BLOB: '/test-blob',
    },
  },
  
  // Helper functions
  getFullUrl: (endpoint: string) => {
    return `${getApiBaseUrl()}${endpoint}`;
  },
  
  // Default headers
  getHeaders: (token?: string) => {
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
    };
    
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    
    return headers;
  },
};