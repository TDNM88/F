import bcrypt from "bcryptjs"

export async function hashPassword(password: string): Promise<string> {
  const saltRounds = 12
  return await bcrypt.hash(password, saltRounds)
}

export async function comparePassword(password: string, hashedPassword: string): Promise<boolean> {
  return await bcrypt.compare(password, hashedPassword)
}

export function generateToken(userId: string): string {
  return `user_${userId}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
}

export function parseToken(token: string): { userId: string; timestamp: number } | null {
  try {
    console.log('Parsing token:', token);
    
    // Handle JWT token format
    if (token.startsWith('eyJ') && token.split('.').length === 3) {
      console.log('Detected JWT token format');
      const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
      return {
        userId: payload.id || payload.userId || '',
        timestamp: payload.iat ? payload.iat * 1000 : Date.now()
      };
    }
    
    // Handle custom token format: user_<userId>_<timestamp>_<random>
    const parts = token.split('_');
    if (parts.length >= 3 && parts[0] === 'user') {
      console.log('Detected custom token format');
      // Extract userId and timestamp
      const userId = parts[1];
      const timestamp = Number(parts[2]);
      
      if (!isNaN(timestamp) && userId) {
        return { userId, timestamp };
      }
    }
    
    console.error('Invalid token format');
    return null;
  } catch (error) {
    console.error('Error parsing token:', error);
    return null;
  }
}

export async function verifyToken(token: string): Promise<{ userId: string; isValid: boolean }> {
  try {
    if (!token) {
      console.error('No token provided');
      return { userId: '', isValid: false };
    }
    
    console.log('Verifying token:', token.substring(0, 10) + '...');
    
    const parsed = parseToken(token);
    if (!parsed) {
      console.error('Failed to parse token');
      return { userId: '', isValid: false };
    }
    
    if (!parsed.userId) {
      console.error('No userId found in token');
      return { userId: '', isValid: false };
    }
    
    // Check if token is expired (7 days)
    const tokenAge = Date.now() - parsed.timestamp;
    const maxAge = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds
    const isExpired = tokenAge > maxAge;
    
    console.log('Token details:', {
      userId: parsed.userId,
      timestamp: new Date(parsed.timestamp).toISOString(),
      ageHours: (tokenAge / (60 * 60 * 1000)).toFixed(2),
      maxAgeHours: (maxAge / (60 * 60 * 1000)).toFixed(2),
      isExpired,
      currentTime: new Date().toISOString()
    });
    
    if (isExpired) {
      console.error('Token expired');
      return { userId: parsed.userId, isValid: false };
    }
    
    console.log('Token is valid');
    return {
      userId: parsed.userId,
      isValid: true
    };
  } catch (error) {
    console.error('Token verification failed:', error);
    return { userId: '', isValid: false };
  }
}

export async function getUserFromRequest(req: Request): Promise<{ userId: string | null; isAuthenticated: boolean }> {
  try {
    // Try to get token from Authorization header first
    const authHeader = req.headers.get('authorization');
    let token: string | null = null;
    
    if (authHeader?.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
      console.log('Found token in Authorization header');
    } 
    // Try to get token from cookie
    else if (req.headers.get('cookie')) {
      const cookies = req.headers.get('cookie')?.split(';').reduce((acc: Record<string, string>, cookie) => {
        const [key, value] = cookie.trim().split('=');
        acc[key] = value;
        return acc;
      }, {});
      
      // Check for both auth_token and token cookie names
      token = cookies?.auth_token || cookies?.token || null;
      
      if (token) {
        console.log('Found token in cookie');
      }
    }
    
    if (!token) {
      console.error('No token found in request');
      return { userId: null, isAuthenticated: false };
    }
    
    console.log('Token found, length:', token.length);
    
    const { userId, isValid } = await verifyToken(token);
    
    if (isValid) {
      console.log('Token is valid for user ID:', userId);
    } else {
      console.error('Token is invalid');
    }
    
    return {
      userId: isValid ? userId : null,
      isAuthenticated: isValid
    };
  } catch (error) {
    console.error('Error getting user from request:', error);
    return { userId: null, isAuthenticated: false };
  }
}
