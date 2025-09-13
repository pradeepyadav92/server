const { Pool } = require('pg');
require('dotenv').config();

// Create PostgreSQL connection pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
});

// Test connection
async function testConnection() {
    try {
        const client = await pool.connect();
        console.log('✅ PostgreSQL Database connected successfully');
        client.release();
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
        process.exit(1);
    }
}

// Initialize database
async function initializeDatabase() {
    try {
        await testConnection();
        
        // Create tables if they don't exist
        await createTables();
        
        // Check if global room exists, if not create it
        const result = await pool.query('SELECT id FROM rooms WHERE name = $1', ['global']);
        if (result.rows.length === 0) {
            // Create a default user first if needed
            const userResult = await pool.query('SELECT id FROM users LIMIT 1');
            let userId = 1;
            
            if (userResult.rows.length === 0) {
                const insertUserResult = await pool.query(
                    'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id',
                    ['system', 'system@chat.app', 'system']
                );
                userId = insertUserResult.rows[0].id;
            } else {
                userId = userResult.rows[0].id;
            }
            
            await pool.query(
                'INSERT INTO rooms (name, created_by) VALUES ($1, $2)',
                ['global', userId]
            );
            console.log('✅ Global room created');
        }
    } catch (error) {
        console.error('❌ Database initialization failed:', error.message);
    }
}

// Create tables function
async function createTables() {
    try {
        // Create users table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                is_online BOOLEAN DEFAULT FALSE,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Create rooms table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS rooms (
                id SERIAL PRIMARY KEY,
                name VARCHAR(50) UNIQUE NOT NULL,
                created_by INTEGER REFERENCES users(id),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Create room_members table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS room_members (
                id SERIAL PRIMARY KEY,
                room_id INTEGER REFERENCES rooms(id),
                user_id INTEGER REFERENCES users(id),
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(room_id, user_id)
            )
        `);

        // Create messages table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                sender_id INTEGER REFERENCES users(id),
                receiver_id INTEGER REFERENCES users(id) DEFAULT NULL,
                room VARCHAR(50) DEFAULT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        console.log('✅ Database tables created/verified');
    } catch (error) {
        console.error('❌ Error creating tables:', error.message);
        throw error;
    }
}

// Helper function to convert MySQL queries to PostgreSQL
function convertQuery(query, params) {
    // Convert MySQL placeholders (?) to PostgreSQL placeholders ($1, $2, etc.)
    let convertedQuery = query;
    let paramIndex = 1;
    
    while (convertedQuery.includes('?')) {
        convertedQuery = convertedQuery.replace('?', `$${paramIndex}`);
        paramIndex++;
    }
    
    return { query: convertedQuery, params };
}

// Wrapper function to maintain compatibility with your existing code
pool.execute = async function(query, params = []) {
    try {
        const converted = convertQuery(query, params);
        const result = await pool.query(converted.query, converted.params);
        
        // Return in MySQL format [rows, fields] for compatibility
        return [result.rows, result.fields];
    } catch (error) {
        console.error('Query error:', error.message);
        throw error;
    }
};

module.exports = { pool, initializeDatabase };