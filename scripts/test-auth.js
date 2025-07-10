import axios from 'axios';
import https from 'https';

// Create axios instance that doesn't reject on HTTP error status codes
const api = axios.create({
  baseURL: 'http://localhost:3000/api',
  withCredentials: true,
  httpsAgent: new https.Agent({  
    rejectUnauthorized: false // Only for localhost testing
  })
});

// Test user credentials
const testUser = {
  username: 'testuser',
  password: 'testpassword123',
  email: 'test@example.com'
};

// Helper function to log test results
function logTestResult(testName, passed, message = '') {
  console.log(`[${passed ? 'PASS' : 'FAIL'}] ${testName}`);
  if (message) {
    console.log(`  ${message}`);
  }
  return passed;
}

// 1. Test registration
async function testRegistration() {
  console.log('  - Sending registration request...');
  console.log('  - URL:', api.defaults.baseURL + '/register');
  console.log('  - Request data:', JSON.stringify({
    username: testUser.username,
    email: testUser.email,
    password: '***',
    confirmPassword: '***'
  }, null, 2));
  
  try {
    const response = await api.post('/register', {
      username: testUser.username,
      email: testUser.email,
      password: testUser.password,
      confirmPassword: testUser.password
    });

    const passed = response.status === 200 && response.data.success;
    return logTestResult(
      'User Registration', 
      passed,
      passed ? 'User registered successfully' : `Failed: ${response.data.message || 'Unknown error'}`
    );
  } catch (error) {
    if (error.response && error.response.status === 400) {
      return logTestResult(
        'User Registration', 
        true, 
        'User already exists (this is expected if test was run before)'
      );
    }
    return logTestResult(
      'User Registration', 
      false, 
      `Error: ${error.response?.data?.message || error.message}`
    );
  }
}

// 2. Test login
async function testLogin() {
  try {
    const response = await api.post('/login', {
      username: testUser.username,
      password: testUser.password
    });

    const passed = response.status === 200 && response.data.success;
    const cookies = response.headers['set-cookie'] || [];
    const hasAuthCookie = cookies.some(cookie => 
      cookie.includes('auth_token=') || cookie.includes('token=')
    );

    logTestResult(
      'User Login - Status', 
      passed,
      passed ? 'Login successful' : `Failed: ${response.data.message || 'Unknown error'}`
    );

    logTestResult(
      'User Login - Cookies',
      hasAuthCookie,
      hasAuthCookie ? 'Auth cookies found' : 'No auth cookies found in response'
    );

    return passed && hasAuthCookie;
  } catch (error) {
    return logTestResult(
      'User Login', 
      false, 
      `Error: ${error.response?.data?.message || error.message}`
    );
  }
}

// 3. Test protected route (me)
async function testProtectedRoute() {
  try {
    const response = await api.get('/auth/me');
    const passed = response.status === 200 && response.data.success;
    
    logTestResult(
      'Protected Route - Status',
      passed,
      passed ? 'Access granted to protected route' : `Access denied: ${response.data.message || 'Unknown error'}`
    );

    if (passed) {
      console.log('  User data:', {
        id: response.data.user?.id,
        username: response.data.user?.username,
        role: response.data.user?.role
      });
    }

    return passed;
  } catch (error) {
    return logTestResult(
      'Protected Route', 
      false, 
      `Error: ${error.response?.data?.message || error.message}`
    );
  }
}

// 4. Test logout
async function testLogout() {
  try {
    const response = await api.post('/auth/logout');
    const passed = response.status === 200 && response.data.success;
    
    logTestResult(
      'User Logout',
      passed,
      passed ? 'Logout successful' : `Failed: ${response.data.message || 'Unknown error'}`
    );

    // Verify session is invalidated
    if (passed) {
      try {
        await api.get('/auth/me');
        logTestResult(
          'Session Invalidation',
          false,
          'Session still valid after logout'
        );
        return false;
      } catch (error) {
        logTestResult(
          'Session Invalidation',
          error.response?.status === 401,
          'Session successfully invalidated after logout'
        );
      }
    }

    return passed;
  } catch (error) {
    return logTestResult(
      'User Logout', 
      false, 
      `Error: ${error.response?.data?.message || error.message}`
    );
  }
}

// Run all tests
async function runTests() {
  console.log('=== Starting Authentication Tests ===\n');
  
  try {
    console.log('1. Testing registration...');
    const registrationResult = await testRegistration();
    
    console.log('\n2. Testing login...');
    const loginResult = await testLogin();
    
    console.log('\n3. Testing protected route...');
    const protectedRouteResult = await testProtectedRoute();
    
    console.log('\n4. Testing logout...');
    const logoutResult = await testLogout();
    
    const results = {
      registration: registrationResult,
      login: loginResult,
      protectedRoute: protectedRouteResult,
      logout: logoutResult
    };

    const allPassed = Object.values(results).every(Boolean);
    
    console.log('\n=== Test Results ===');
    console.log('Registration:', registrationResult ? 'PASS' : 'FAIL');
    console.log('Login:', loginResult ? 'PASS' : 'FAIL');
    console.log('Protected Route:', protectedRouteResult ? 'PASS' : 'FAIL');
    console.log('Logout:', logoutResult ? 'PASS' : 'FAIL');
    console.log('\nOverall:', allPassed ? 'ALL TESTS PASSED' : 'SOME TESTS FAILED');
    console.log('==================');
    
    process.exit(allPassed ? 0 : 1);
  } catch (error) {
    console.error('\n=== TEST ERROR ===');
    console.error('An error occurred during testing:');
    console.error(error);
    if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response data:', error.response.data);
    }
    console.error('==================');
    process.exit(1);
  }
}

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

runTests();
