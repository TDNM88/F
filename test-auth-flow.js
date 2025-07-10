import axios from 'axios';
import { config } from 'dotenv';
import https from 'https';

// Load environment variables
config();

// Create axios instance that will save cookies between requests
const client = axios.create({
  baseURL: process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000',
  withCredentials: true,
  httpsAgent: new https.Agent({ rejectUnauthorized: false }), // Only for development
});

// Test user credentials
const TEST_USER = {
  username: `testuser_${Date.now()}`,
  email: `test_${Date.now()}@example.com`,
  password: 'Test@12345',
};

// Parse command line arguments
const args = process.argv.slice(2);

// Check if admin credentials are provided
if (args.length < 2) {
  console.error('Please provide admin email and password as arguments:');
  console.error('  node test-auth-flow.js <admin-email> <admin-password>');
  process.exit(1);
}

// Test admin credentials (should be pre-created in the database)
const ADMIN_CREDENTIALS = {
  email: args[0],
  password: args[1],
};

// Utility function to clear test user
async function cleanupTestUser() {
  try {
    // First login as admin
    const loginRes = await client.post('/api/auth/login', {
      email: ADMIN_CREDENTIALS.email,
      password: ADMIN_CREDENTIALS.password,
    });

    if (loginRes.data.success) {
      // Delete test user if exists
      await client.delete('/api/admin/users', {
        data: { username: TEST_USER.username },
        headers: { Cookie: loginRes.headers['set-cookie']?.join('; ') },
      });
      console.log('Cleaned up test user');
    }
  } catch (error) {
    console.log('Cleanup skipped or failed:', error.message);
  }
}

// Test cases
async function runTests() {
  console.log('Starting authentication flow tests...\n');

  try {
    // 1. Clean up any existing test user
    await cleanupTestUser();

    // 2. Test registration
    console.log('1. Testing user registration...');
    const registerResponse = await client.post('/api/auth/register', {
      username: TEST_USER.username,
      email: TEST_USER.email,
      password: TEST_USER.password,
    });

    if (!registerResponse.data.success) {
      throw new Error('Registration failed: ' + registerResponse.data.message);
    }
    console.log('✅ Registration successful');

    // 3. Test login with wrong credentials
    console.log('\n2. Testing login with wrong credentials...');
    try {
      await client.post('/api/auth/login', {
        email: TEST_USER.email,
        password: 'wrongpassword',
      });
      throw new Error('Login with wrong password should fail');
    } catch (error) {
      if (error.response?.status === 401) {
        console.log('✅ Failed login with wrong credentials (expected)');
      } else {
        throw error;
      }
    }

    // 4. Test login with correct credentials
    console.log('\n3. Testing login with correct credentials...');
    const loginResponse = await client.post('/api/auth/login', {
      email: TEST_USER.email,
      password: TEST_USER.password,
    });

    if (!loginResponse.data.success) {
      throw new Error('Login failed: ' + loginResponse.data.message);
    }
    console.log('✅ Login successful');

    // Save cookies for subsequent requests
    const cookies = loginResponse.headers['set-cookie'];
    const authHeader = { Cookie: cookies?.join('; ') };

    // 5. Test accessing protected route
    console.log('\n4. Testing access to protected route...');
    const meResponse = await client.get('/api/auth/me', { headers: authHeader });
    if (!meResponse.data.success) {
      throw new Error('Failed to access protected route: ' + meResponse.data.message);
    }
    console.log('✅ Successfully accessed protected route');
    console.log('   User data:', JSON.stringify(meResponse.data.data, null, 2));

    // 6. Test role-based access control (should fail for regular user)
    console.log('\n5. Testing admin-only route access...');
    try {
      await client.get('/api/admin/users', { headers: authHeader });
      throw new Error('Regular user should not access admin route');
    } catch (error) {
      if (error.response?.status === 403) {
        console.log('✅ Regular user correctly blocked from admin route');
      } else {
        throw error;
      }
    }

    // 7. Test admin login and access
    console.log('\n6. Testing admin login and access...');
    const adminLogin = await client.post('/api/auth/login', {
      email: ADMIN_CREDENTIALS.email,
      password: ADMIN_CREDENTIALS.password,
    });

    if (!adminLogin.data.success) {
      throw new Error('Admin login failed: ' + adminLogin.data.message);
    }

    const adminCookies = adminLogin.headers['set-cookie'];
    const adminAuthHeader = { Cookie: adminCookies?.join('; ') };

    const adminUsersResponse = await client.get('/api/admin/users', { 
      headers: adminAuthHeader 
    });
    
    if (!adminUsersResponse.data.success) {
      throw new Error('Admin route access failed: ' + adminUsersResponse.data.message);
    }
    console.log('✅ Admin access to admin route successful');

    // 8. Test logout
    console.log('\n7. Testing logout...');
    const logoutResponse = await client.post('/api/auth/logout', {}, { 
      headers: authHeader 
    });

    if (!logoutResponse.data.success) {
      throw new Error('Logout failed: ' + logoutResponse.data.message);
    }
    console.log('✅ Logout successful');

    // 9. Verify session is invalid after logout
    console.log('\n8. Verifying session after logout...');
    try {
      await client.get('/api/auth/me', { headers: authHeader });
      throw new Error('Session should be invalid after logout');
    } catch (error) {
      if (error.response?.status === 401) {
        console.log('✅ Session correctly invalidated after logout');
      } else {
        throw error;
      }
    }

    console.log('\n🎉 All authentication tests passed successfully!');

  } catch (error) {
    console.error('\n❌ Test failed:', error.message);
    if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response data:', error.response.data);
    }
    process.exit(1);
  } finally {
    // Clean up test user
    await cleanupTestUser();
  }
}

// Run the tests
runTests();
