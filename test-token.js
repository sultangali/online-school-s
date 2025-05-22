import jwt from 'jsonwebtoken';
import config from 'config';

// Function to test token verification
const testToken = (token) => {
    console.log('Starting token test...');
    
    try {
        // Check if we're in production mode
        console.log('Environment:', process.env.NODE_ENV || 'development');
        
        // Print which config file we're using
        console.log('Config files loaded:', config.util.getConfigSources().map(s => s.name));
        
        // Get the JWT key
        const jwtKey = config.get('jwt_key');
        console.log('JWT Key being used:', jwtKey.substring(0, 3) + '...');
        
        if (!token || token === 'undefined') {
            console.log('⚠️ No token provided for testing');
            return;
        }
        
        // Test the token verification
        const decoded = jwt.verify(token, jwtKey);
        console.log('✅ Token verified successfully!');
        console.log('Token payload:', decoded);
    } catch (error) {
        console.log('❌ Token verification failed:', error.message);
    }
};

// If called directly from command line, use the provided token
if (process.argv[2]) {
    testToken(process.argv[2]);
} else {
    console.log('Usage: node test-token.js <your-token>');
}

// Export for use in other files
export default testToken; 