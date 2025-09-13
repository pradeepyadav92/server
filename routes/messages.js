const express = require('express');
const { body, query, param, validationResult } = require('express-validator');
const { pool } = require('../db');
const { authenticateToken } = require('./auth');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

const router = express.Router();

// Get room messages
router.get('/room/:roomName', 
    authenticateToken,
    param('roomName').notEmpty().withMessage('Room name is required'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
    query('offset').optional().isInt({ min: 0 }).withMessage('Offset must be non-negative'),
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    message: 'Validation failed',
                    errors: errors.array()
                });
            }

            const { roomName } = req.params;
            const limit = parseInt(req.query.limit) || 50;
            const offset = parseInt(req.query.offset) || 0;

            // Check if room exists
            const [rooms] = await pool.execute(
                'SELECT id FROM rooms WHERE name = ?',
                [roomName]
            );

            if (rooms.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Room not found'
                });
            }

            // Check if user is member of the room (except for global room)
            if (roomName !== 'global') {
                const [membership] = await pool.execute(
                    'SELECT 1 FROM room_members rm JOIN rooms r ON rm.room_id = r.id WHERE r.name = ? AND rm.user_id = ?',
                    [roomName, req.user.userId]
                );

                if (membership.length === 0) {
                    return res.status(403).json({
                        success: false,
                        message: 'You are not a member of this room'
                    });
                }
            }

            // Get messages
            const [messages] = await pool.execute(`
                SELECT 
                    m.id,
                    m.content,
                    m.created_at,
                    u.username as sender_username,
                    u.id as sender_id
                FROM messages m
                JOIN users u ON m.sender_id = u.id
                WHERE m.room = ?
                ORDER BY m.created_at DESC
                LIMIT ? OFFSET ?
            `, [roomName, limit, offset]);

            // Reverse to show oldest first
            messages.reverse();

            res.json({
                success: true,
                data: {
                    messages,
                    hasMore: messages.length === limit
                }
            });

        } catch (error) {
            console.error('Get room messages error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }
);

// Get private messages
router.get('/private/:userId',
    authenticateToken,
    param('userId').isInt().withMessage('User ID must be an integer'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
    query('offset').optional().isInt({ min: 0 }).withMessage('Offset must be non-negative'),
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    message: 'Validation failed',
                    errors: errors.array()
                });
            }

            const { userId } = req.params;
            const limit = parseInt(req.query.limit) || 50;
            const offset = parseInt(req.query.offset) || 0;
            const currentUserId = req.user.userId;

            // Check if target user exists
            const [users] = await pool.execute(
                'SELECT id, username FROM users WHERE id = ?',
                [userId]
            );

            if (users.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found'
                });
            }

            // Get private messages between current user and target user
            const [messages] = await pool.execute(`
                SELECT 
                    m.id,
                    m.content,
                    m.created_at,
                    u.username as sender_username,
                    u.id as sender_id,
                    CASE 
                        WHEN m.sender_id = ? THEN 'sent'
                        ELSE 'received'
                    END as direction
                FROM messages m
                JOIN users u ON m.sender_id = u.id
                WHERE m.room IS NULL 
                AND (
                    (m.sender_id = ? AND m.receiver_id = ?) OR 
                    (m.sender_id = ? AND m.receiver_id = ?)
                )
                ORDER BY m.created_at DESC
                LIMIT ? OFFSET ?
            `, [currentUserId, currentUserId, userId, userId, currentUserId, limit, offset]);

            // Reverse to show oldest first
            messages.reverse();

            res.json({
                success: true,
                data: {
                    messages,
                    targetUser: users[0],
                    hasMore: messages.length === limit
                }
            });

        } catch (error) {
            console.error('Get private messages error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }
);

// Get user's rooms
router.get('/rooms', authenticateToken, async (req, res) => {
    try {
        const [rooms] = await pool.execute(`
            SELECT DISTINCT
                r.id,
                r.name,
                r.created_at,
                u.username as created_by_username,
                (
                    SELECT COUNT(*) 
                    FROM room_members rm2 
                    WHERE rm2.room_id = r.id
                ) as member_count
            FROM rooms r
            LEFT JOIN room_members rm ON r.id = rm.room_id
            LEFT JOIN users u ON r.created_by = u.id
            WHERE r.name = 'global' OR rm.user_id = ?
            ORDER BY r.name
        `, [req.user.userId]);

        res.json({
            success: true,
            data: { rooms }
        });

    } catch (error) {
        console.error('Get rooms error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Create room
router.post('/rooms',
    authenticateToken,
    body('name')
        .isLength({ min: 1, max: 100 })
        .matches(/^[a-zA-Z0-9_-]+$/)
        .withMessage('Room name must be 1-100 characters and contain only letters, numbers, hyphens, and underscores'),
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    message: 'Validation failed',
                    errors: errors.array()
                });
            }

            const { name } = req.body;
            const userId = req.user.userId;

            // Check if room already exists
            const [existingRooms] = await pool.execute(
                'SELECT id FROM rooms WHERE name = ?',
                [name]
            );

            if (existingRooms.length > 0) {
                return res.status(409).json({
                    success: false,
                    message: 'Room already exists'
                });
            }

            // Create room
            const [roomResult] = await pool.execute(
                'INSERT INTO rooms (name, created_by) VALUES (?, ?)',
                [name, userId]
            );

            // Add creator as member
            await pool.execute(
                'INSERT INTO room_members (room_id, user_id) VALUES (?, ?)',
                [roomResult.insertId, userId]
            );

            res.status(201).json({
                success: true,
                message: 'Room created successfully',
                data: {
                    room: {
                        id: roomResult.insertId,
                        name,
                        created_by: userId
                    }
                }
            });

        } catch (error) {
            console.error('Create room error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }
);

// Join room
router.post('/rooms/:roomName/join',
    authenticateToken,
    param('roomName').notEmpty().withMessage('Room name is required'),
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    message: 'Validation failed',
                    errors: errors.array()
                });
            }

            const { roomName } = req.params;
            const userId = req.user.userId;

            // Check if room exists
            const [rooms] = await pool.execute(
                'SELECT id FROM rooms WHERE name = ?',
                [roomName]
            );

            if (rooms.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Room not found'
                });
            }

            const roomId = rooms[0].id;

            // Check if already a member
            const [membership] = await pool.execute(
                'SELECT 1 FROM room_members WHERE room_id = ? AND user_id = ?',
                [roomId, userId]
            );

            if (membership.length > 0) {
                return res.status(409).json({
                    success: false,
                    message: 'Already a member of this room'
                });
            }

            // Add user to room
            await pool.execute(
                'INSERT INTO room_members (room_id, user_id) VALUES (?, ?)',
                [roomId, userId]
            );

            res.json({
                success: true,
                message: 'Successfully joined room'
            });

        } catch (error) {
            console.error('Join room error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }
);

module.exports = router;