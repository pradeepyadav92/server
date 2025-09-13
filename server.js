const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { pool, initializeDatabase } = require('./db');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: process.env.CLIENT_URL || "*",
        methods: ["GET", "POST"]
    }
});

// Middleware
app.use(express.json());

// Serve static files from public directory
app.use(express.static(path.join(__dirname, 'public')));

// Store online users
const onlineUsers = new Map();

// Socket.IO Authentication Middleware
io.use(async (socket, next) => {
    try {
        const token = socket.handshake.auth.token;
        if (!token) {
            return next(new Error('Authentication error'));
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const [rows] = await pool.execute(
            'SELECT id, username, email FROM users WHERE id = ?',
            [decoded.userId]
        );

        if (rows.length === 0) {
            return next(new Error('User not found'));
        }

        socket.user = rows[0];
        next();
    } catch (error) {
        next(new Error('Authentication error'));
    }
});

// Socket.IO Connection Handling
io.on('connection', async (socket) => {
    console.log(`👤 User connected: ${socket.user.username} (${socket.id})`);
    
    // Add user to online users
    onlineUsers.set(socket.user.id, {
        id: socket.user.id,
        username: socket.user.username,
        socketId: socket.id
    });

    // Update user as online in database
    await pool.execute(
        'UPDATE users SET is_online = TRUE, last_seen = NOW() WHERE id = ?',
        [socket.user.id]
    );

    // Broadcast updated user list
    broadcastUserList();

    // Send room list to user
    await sendRoomList(socket);

    // Join user to global room by default
    socket.join('global');
    console.log(`🏠 ${socket.user.username} joined global room`);

    // Send recent messages from global room
    await sendRecentMessages(socket, 'global');

    // Handle joining rooms
    socket.on('join-room', async (roomName) => {
        try {
            console.log(`🏠 ${socket.user.username} joining room: ${roomName}`);
            
            // Leave current rooms (except socket.id room)
            const rooms = Array.from(socket.rooms);
            rooms.forEach(room => {
                if (room !== socket.id) {
                    socket.leave(room);
                }
            });

            // Join new room
            socket.join(roomName);
            socket.currentRoom = roomName;

            // Add user to room_members if not already there
            await pool.execute(
                `INSERT IGNORE INTO room_members (room_id, user_id) 
                 SELECT r.id, ? FROM rooms r WHERE r.name = ?`,
                [socket.user.id, roomName]
            );

            // Send recent messages from this room
            await sendRecentMessages(socket, roomName);

            // Notify room about user joining
            socket.to(roomName).emit('user-joined', {
                username: socket.user.username,
                room: roomName
            });

            console.log(`✅ ${socket.user.username} successfully joined ${roomName}`);
        } catch (error) {
            console.error('Error joining room:', error);
            socket.emit('error', 'Failed to join room');
        }
    });

    // Handle sending messages to rooms
    socket.on('message', async (data) => {
        try {
            console.log(`💬 Message from ${socket.user.username} to room ${data.room}:`, data.content);

            if (!data.content || !data.content.trim()) {
                return;
            }

            const message = {
                id: Date.now(), // Temporary ID
                sender: {
                    id: socket.user.id,
                    username: socket.user.username
                },
                content: data.content.trim(),
                room: data.room,
                created_at: new Date().toISOString()
            };

            // Save message to database
            const [result] = await pool.execute(
                'INSERT INTO messages (sender_id, room, content, created_at) VALUES (?, ?, ?, NOW())',
                [socket.user.id, data.room, message.content]
            );

            message.id = result.insertId;

            // Broadcast message to all users in the room (including sender)
            io.to(data.room).emit('message', message);
            
            console.log(`📤 Message broadcasted to room ${data.room}`);
        } catch (error) {
            console.error('Error sending message:', error);
            socket.emit('error', 'Failed to send message');
        }
    });

    // Handle private messages
    socket.on('private-message', async (data) => {
        try {
            console.log(`💌 Private message from ${socket.user.username} to ${data.to}`);

            if (!data.content || !data.content.trim()) {
                return;
            }

            // Find recipient user
            const [recipientRows] = await pool.execute(
                'SELECT id, username FROM users WHERE username = ?',
                [data.to]
            );

            if (recipientRows.length === 0) {
                socket.emit('error', 'User not found');
                return;
            }

            const recipient = recipientRows[0];

            const message = {
                id: Date.now(),
                sender: {
                    id: socket.user.id,
                    username: socket.user.username
                },
                recipient: {
                    id: recipient.id,
                    username: recipient.username
                },
                content: data.content.trim(),
                created_at: new Date().toISOString()
            };

            // Save private message to database
            const [result] = await pool.execute(
                'INSERT INTO messages (sender_id, receiver_id, content, created_at) VALUES (?, ?, ?, NOW())',
                [socket.user.id, recipient.id, message.content]
            );

            message.id = result.insertId;

            // Send to recipient if online
            const recipientUser = onlineUsers.get(recipient.id);
            if (recipientUser) {
                io.to(recipientUser.socketId).emit('private-message', message);
            }

            // Send back to sender
            socket.emit('private-message', message);

            console.log(`📤 Private message sent between ${socket.user.username} and ${data.to}`);
        } catch (error) {
            console.error('Error sending private message:', error);
            socket.emit('error', 'Failed to send private message');
        }
    });

    // Handle creating rooms
    socket.on('create-room', async (roomName) => {
        try {
            console.log(`🏗️ ${socket.user.username} creating room: ${roomName}`);

            if (!roomName || !roomName.trim()) {
                socket.emit('error', 'Room name cannot be empty');
                return;
            }

            const trimmedName = roomName.trim();

            // Check if room already exists
            const [existingRoom] = await pool.execute(
                'SELECT id FROM rooms WHERE name = ?',
                [trimmedName]
            );

            if (existingRoom.length > 0) {
                socket.emit('error', 'Room already exists');
                return;
            }

            // Create room
            await pool.execute(
                'INSERT INTO rooms (name, created_by) VALUES (?, ?)',
                [trimmedName, socket.user.id]
            );

            // Add creator to room members
            const [roomResult] = await pool.execute(
                'SELECT id FROM rooms WHERE name = ?',
                [trimmedName]
            );

            await pool.execute(
                'INSERT INTO room_members (room_id, user_id) VALUES (?, ?)',
                [roomResult[0].id, socket.user.id]
            );

            // Broadcast updated room list to all users
            broadcastRoomList();

            // Auto-join the creator to the new room
            socket.join(trimmedName);
            socket.currentRoom = trimmedName;

            console.log(`✅ Room ${trimmedName} created successfully`);
        } catch (error) {
            console.error('Error creating room:', error);
            socket.emit('error', 'Failed to create room');
        }
    });

    // Handle disconnection
    socket.on('disconnect', async () => {
        console.log(`👋 User disconnected: ${socket.user.username}`);
        
        // Remove from online users
        onlineUsers.delete(socket.user.id);
        
        // Update user as offline in database
        await pool.execute(
            'UPDATE users SET is_online = FALSE, last_seen = NOW() WHERE id = ?',
            [socket.user.id]
        );
        
        // Broadcast updated user list
        broadcastUserList();
    });
});

// Helper Functions
async function sendRecentMessages(socket, roomName) {
    try {
        const [messages] = await pool.execute(
            `SELECT m.id, m.content, m.created_at, u.id as sender_id, u.username as sender_username
             FROM messages m
             JOIN users u ON m.sender_id = u.id
             WHERE m.room = ?
             ORDER BY m.created_at DESC
             LIMIT 50`,
            [roomName]
        );

        // Send messages in chronological order
        messages.reverse().forEach(msg => {
            socket.emit('message', {
                id: msg.id,
                sender: {
                    id: msg.sender_id,
                    username: msg.sender_username
                },
                content: msg.content,
                room: roomName,
                created_at: msg.created_at
            });
        });
    } catch (error) {
        console.error('Error sending recent messages:', error);
    }
}

async function sendRoomList(socket) {
    try {
        const [rooms] = await pool.execute('SELECT name FROM rooms ORDER BY name');
        socket.emit('room-list', rooms);
    } catch (error) {
        console.error('Error sending room list:', error);
    }
}

async function broadcastRoomList() {
    try {
        const [rooms] = await pool.execute('SELECT name FROM rooms ORDER BY name');
        io.emit('room-list', rooms);
    } catch (error) {
        console.error('Error broadcasting room list:', error);
    }
}

function broadcastUserList() {
    const users = Array.from(onlineUsers.values());
    io.emit('user-list', users);
}

// Authentication Routes
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Check if user exists
        const [existingUsers] = await pool.execute(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            [username, email]
        );

        if (existingUsers.length > 0) {
            return res.json({ success: false, message: 'Username or email already exists' });
        }

        // Hash password
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Create user
        const [result] = await pool.execute(
            'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
            [username, email, hashedPassword]
        );

        // Generate JWT token
        const token = jwt.sign(
            { userId: result.insertId },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            token,
            user: { id: result.insertId, username, email }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.json({ success: false, message: 'Registration failed' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find user
        const [users] = await pool.execute(
            'SELECT id, username, email, password_hash FROM users WHERE username = ?',
            [username]
        );

        if (users.length === 0) {
            return res.json({ success: false, message: 'Invalid credentials' });
        }

        const user = users[0];

        // Check password
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.json({ success: false, message: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { userId: user.id },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            token,
            user: { id: user.id, username: user.username, email: user.email }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.json({ success: false, message: 'Login failed' });
    }
});

app.get('/api/verify-token', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ success: false, message: 'No token provided' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const [users] = await pool.execute(
            'SELECT id, username, email FROM users WHERE id = ?',
            [decoded.userId]
        );

        if (users.length === 0) {
            return res.status(401).json({ success: false, message: 'User not found' });
        }

        res.json({ success: true, user: users[0] });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Serve static files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/index.html'));
});

// Initialize global room
async function initializeGlobalRoom() {
    try {
        const [rooms] = await pool.execute('SELECT id FROM rooms WHERE name = ?', ['global']);
        if (rooms.length === 0) {
            await pool.execute('INSERT INTO rooms (name, created_by) VALUES (?, ?)', ['global', 1]);
            console.log('✅ Global room created');
        }
    } catch (error) {
        console.error('Error initializing global room:', error);
    }
}

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, async () => {
    console.log('🔄 Initializing database...');
    await initializeDatabase();
    console.log(`🚀 Server running on port ${PORT}`);
    console.log('📱 Socket.IO ready for connections');
    console.log(`🔒 Environment: ${process.env.NODE_ENV || 'development'}`);
});