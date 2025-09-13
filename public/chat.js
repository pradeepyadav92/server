// Socket.io connection
let socket;
let currentUser = null;
let currentRoom = 'global';
let currentPrivateUser = null;

// DOM Elements
const authContainer = document.getElementById('authContainer');
const chatContainer = document.getElementById('chatContainer');
const loginForm = document.getElementById('loginForm');
const registerForm = document.getElementById('registerForm');
const authMessage = document.getElementById('authMessage');
const currentUsername = document.getElementById('currentUsername');
const logoutBtn = document.getElementById('logoutBtn');

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 Chat application initializing...');
    checkAuth();
    setupEventListeners();
});

function checkAuth() {
    const token = localStorage.getItem('token');
    if (token) {
        console.log('🔍 Checking existing token...');
        // Verify token with server
        fetch('/api/verify-token', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        })
        .then(response => {
            if (response.ok) {
                return response.json();
            }
            throw new Error('Invalid token');
        })
        .then(data => {
            console.log('✅ Token verified, user:', data.user.username);
            currentUser = data.user;
            showChat();
            initializeSocket();
        })
        .catch(error => {
            console.log('❌ Token verification failed:', error.message);
            localStorage.removeItem('token');
            showAuth();
        });
    } else {
        console.log('📝 No token found, showing auth');
        showAuth();
    }
}

function setupEventListeners() {
    // Auth form toggles
    document.getElementById('showRegister').addEventListener('click', (e) => {
        e.preventDefault();
        loginForm.classList.add('hidden');
        registerForm.classList.remove('hidden');
        clearMessages();
    });

    document.getElementById('showLogin').addEventListener('click', (e) => {
        e.preventDefault();
        registerForm.classList.add('hidden');
        loginForm.classList.remove('hidden');
        clearMessages();
    });

    // Form submissions
    document.getElementById('loginFormElement').addEventListener('submit', handleLogin);
    document.getElementById('registerFormElement').addEventListener('submit', handleRegister);
    
    // Logout button
    logoutBtn.addEventListener('click', handleLogout);

    // Chat functionality
    document.getElementById('sendBtn').addEventListener('click', sendMessage);
    document.getElementById('messageInput').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            sendMessage();
        }
    });

    document.getElementById('createRoomBtn').addEventListener('click', createRoom);
}

function handleLogin(e) {
    e.preventDefault();
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;

    if (!username || !password) {
        showError('Please fill all the fields');
        return;
    }

    console.log('🔐 Attempting login for:', username);

    fetch('/api/auth/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            console.log('✅ Login successful for:', data.user.username);
            localStorage.setItem('token', data.token);
            currentUser = data.user;
            showSuccess('Login successful!');
            setTimeout(() => {
                showChat();
                initializeSocket();
            }, 1000);
        } else {
            console.log('❌ Login failed:', data.message);
            showError(data.message);
        }
    })
    .catch(error => {
        console.error('Login error:', error);
        showError('Login failed. Please try again.');
    });
}

function handleRegister(e) {
    e.preventDefault();
    const username = document.getElementById('registerUsername').value.trim();
    const email = document.getElementById('registerEmail').value.trim();
    const password = document.getElementById('registerPassword').value;

    if (!username || !email || !password) {
        showError('Please fill in all fields');
        return;
    }

    if (password.length < 6) {
        showError('Password must be at least 6 characters long');
        return;
    }

    console.log('📝 Attempting registration for:', username);

    fetch('/api/auth/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, email, password }),
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            console.log('✅ Registration successful for:', data.user.username);
            localStorage.setItem('token', data.token);
            currentUser = data.user;
            showSuccess('Registration successful!');
            setTimeout(() => {
                showChat();
                initializeSocket();
            }, 1000);
        } else {
            console.log('❌ Registration failed:', data.message);
            showError(data.message);
        }
    })
    .catch(error => {
        console.error('Registration error:', error);
        showError('Registration failed. Please try again.');
    });
}

function handleLogout() {
    console.log('🚪 Logging out user:', currentUser?.username);
    
    // Disconnect socket
    if (socket) {
        socket.disconnect();
        socket = null;
    }
    
    // Clear local storage
    localStorage.removeItem('token');
    
    // Reset variables
    currentUser = null;
    currentRoom = 'global';
    currentPrivateUser = null;
    
    // Show auth container
    showAuth();
    
    // Clear chat messages
    document.getElementById('chatMessages').innerHTML = `
        <div class="message other">
            <div class="message-header">System</div>
            <div class="message-content">Welcome to the chat! 🎉</div>
            <div class="message-time">Just now</div>
        </div>
    `;
    
    // Clear user and room lists
    document.getElementById('userList').innerHTML = '';
    document.getElementById('roomList').innerHTML = '';
    
    showSuccess('Logged out successfully!');
}

function showAuth() {
    authContainer.classList.remove('hidden');
    chatContainer.classList.add('hidden');
    document.body.style.display = 'flex';
    document.body.style.justifyContent = 'center';
    document.body.style.alignItems = 'center';
}

function showChat() {
    authContainer.classList.add('hidden');
    chatContainer.classList.remove('hidden');
    document.body.style.display = 'block';
    
    // Update username display
    if (currentUser) {
        currentUsername.textContent = `Welcome, ${currentUser.username}!`;
    }
}

function initializeSocket() {
    console.log('🔌 Initializing socket connection...');
    
    socket = io({
        auth: {
            token: localStorage.getItem('token')
        }
    });

    socket.on('connect', () => {
        console.log('✅ Connected to server with socket ID:', socket.id);
        // Auto-join global room
        joinRoom('global');
    });

    socket.on('user-list', (users) => {
        console.log('👥 Received user list:', users.length, 'users');
        updateUserList(users);
    });

    socket.on('room-list', (rooms) => {
        console.log('🏠 Received room list:', rooms.length, 'rooms');
        updateRoomList(rooms);
    });

    socket.on('message', (message) => {
        console.log('💬 Received message:', message);
        if (message.room === currentRoom || !currentRoom) {
            displayMessage(message);
        }
    });

    socket.on('private-message', (message) => {
        console.log('💌 Received private message:', message);
        displayPrivateMessage(message);
    });

    socket.on('user-joined', (data) => {
        console.log('👋 User joined room:', data);
        displaySystemMessage(`${data.username} joined the room`);
    });

    socket.on('disconnect', (reason) => {
        console.log('❌ Disconnected from server:', reason);
        displaySystemMessage('Disconnected from server. Trying to reconnect...');
    });

    socket.on('connect_error', (error) => {
        console.error('🔌 Connection error:', error);
        showError('Connection failed. Please refresh the page.');
    });

    socket.on('error', (error) => {
        console.error('⚠️ Socket error:', error);
        showError(error);
    });

    // Handle reconnection
    socket.on('reconnect', () => {
        console.log('🔄 Reconnected to server');
        displaySystemMessage('Reconnected to server!');
        if (currentRoom) {
            joinRoom(currentRoom);
        }
    });
}

function sendMessage() {
    const input = document.getElementById('messageInput');
    const message = input.value.trim();
    
    if (!message) {
        console.log('❌ Cannot send empty message');
        return;
    }

    if (!socket || !socket.connected) {
        console.log('❌ Socket not connected');
        showError('Not connected to server');
        return;
    }
    
    console.log('📤 Sending message:', message, 'to:', currentPrivateUser ? `user ${currentPrivateUser}` : `room ${currentRoom}`);
    
    if (currentPrivateUser) {
        // Send private message
        socket.emit('private-message', {
            to: currentPrivateUser,
            content: message
        });
    } else if (currentRoom) {
        // Send room message
        socket.emit('message', {
            room: currentRoom,
            content: message
        });
    } else {
        console.log('❌ No active room or private chat');
        showError('Please select a room or user to send messages');
        return;
    }
    
    // Clear input and focus
    input.value = '';
    input.focus();
}

function joinRoom(roomName) {
    if (!socket || !socket.connected) {
        console.log('❌ Cannot join room - socket not connected');
        return;
    }

    console.log('🏠 Joining room:', roomName);
    
    currentRoom = roomName;
    currentPrivateUser = null;
    
    socket.emit('join-room', roomName);
    
    // Update UI to show current room
    document.querySelectorAll('.room-list li').forEach(li => {
        li.classList.remove('active');
        if (li.textContent.includes(roomName)) {
            li.classList.add('active');
        }
    });
    
    // Clear active user selection
    document.querySelectorAll('.user-list li').forEach(li => {
        li.classList.remove('active');
    });
    
    // Clear messages and show loading
    const messagesContainer = document.getElementById('chatMessages');
    messagesContainer.innerHTML = `
        <div class="message other">
            <div class="message-header">System</div>
            <div class="message-content">Loading messages from ${roomName}...</div>
            <div class="message-time">${new Date().toLocaleTimeString()}</div>
        </div>
    `;
    
    // Focus message input
    document.getElementById('messageInput').focus();
}

function startPrivateChat(username) {
    if (username === currentUser.username) {
        console.log('❌ Cannot start private chat with yourself');
        return;
    }

    console.log('💌 Starting private chat with:', username);
    
    currentPrivateUser = username;
    currentRoom = null;
    
    // Update UI
    document.querySelectorAll('.room-list li').forEach(li => {
        li.classList.remove('active');
    });
    
    document.querySelectorAll('.user-list li').forEach(li => {
        li.classList.remove('active');
        if (li.textContent.includes(username)) {
            li.classList.add('active');
        }
    });
    
    // Clear messages and show private chat header
    const messagesContainer = document.getElementById('chatMessages');
    messagesContainer.innerHTML = `
        <div class="message other">
            <div class="message-header">System</div>
            <div class="message-content">Private chat with ${username} 💌</div>
            <div class="message-time">${new Date().toLocaleTimeString()}</div>
        </div>
    `;
    
    // Focus message input
    document.getElementById('messageInput').focus();
}

function createRoom() {
    const roomName = prompt('Enter room name:');
    if (!roomName || !roomName.trim()) {
        return;
    }

    const trimmedName = roomName.trim();
    
    if (trimmedName.length < 2) {
        showError('Room name must be at least 2 characters long');
        return;
    }

    if (trimmedName.length > 20) {
        showError('Room name must be less than 20 characters');
        return;
    }

    if (!socket || !socket.connected) {
        showError('Not connected to server');
        return;
    }

    console.log('🏗️ Creating room:', trimmedName);
    socket.emit('create-room', trimmedName);
}

function updateUserList(users) {
    const userList = document.getElementById('userList');
    userList.innerHTML = '';
    
    console.log('👥 Updating user list with', users.length, 'users');
    
    users.forEach(user => {
        if (user.username !== currentUser.username) {
            const li = document.createElement('li');
            li.innerHTML = `
                <span class="online-indicator"></span>
                <span>${escapeHtml(user.username)}</span>
            `;
            li.addEventListener('click', () => startPrivateChat(user.username));
            li.title = `Click to start private chat with ${user.username}`;
            userList.appendChild(li);
        }
    });

    if (users.length <= 1) {
        const li = document.createElement('li');
        li.innerHTML = `<span style="opacity: 0.6;">No other users online</span>`;
        li.style.cursor = 'default';
        userList.appendChild(li);
    }
}

function updateRoomList(rooms) {
    const roomList = document.getElementById('roomList');
    roomList.innerHTML = '';
    
    console.log('🏠 Updating room list with', rooms.length, 'rooms');
    
    rooms.forEach(room => {
        const li = document.createElement('li');
        li.innerHTML = `🏠 ${escapeHtml(room.name)}`;
        li.addEventListener('click', () => joinRoom(room.name));
        li.title = `Click to join ${room.name} room`;
        
        // Highlight current room
        if (room.name === currentRoom) {
            li.classList.add('active');
        }
        
        roomList.appendChild(li);
    });

    if (rooms.length === 0) {
        const li = document.createElement('li');
        li.innerHTML = `<span style="opacity: 0.6;">No rooms available</span>`;
        li.style.cursor = 'default';
        roomList.appendChild(li);
    }
}

function displayMessage(message) {
    const messagesContainer = document.getElementById('chatMessages');
    
    // Remove loading message if present
    const loadingMessages = messagesContainer.querySelectorAll('.message .message-content');
    loadingMessages.forEach(msg => {
        if (msg.textContent.includes('Loading messages')) {
            msg.parentElement.remove();
        }
    });
    
    const messageDiv = document.createElement('div');
    const isOwn = message.sender.username === currentUser.username;
    
    messageDiv.className = `message ${isOwn ? 'own' : 'other'}`;
    messageDiv.innerHTML = `
        <div class="message-header">${escapeHtml(message.sender.username)}</div>
        <div class="message-content">${escapeHtml(message.content)}</div>
        <div class="message-time">${formatTime(message.created_at)}</div>
    `;
    
    messagesContainer.appendChild(messageDiv);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
    
    console.log('✅ Message displayed from:', message.sender.username);
}

function displayPrivateMessage(message) {
    const messagesContainer = document.getElementById('chatMessages');
    const messageDiv = document.createElement('div');
    
    const isOwn = message.sender.username === currentUser.username;
    const otherUser = isOwn ? message.recipient.username : message.sender.username;
    
    messageDiv.className = `message ${isOwn ? 'own' : 'other'}`;
    messageDiv.innerHTML = `
        <div class="message-header">${escapeHtml(message.sender.username)} ${isOwn ? '→' : '→'} ${escapeHtml(otherUser)} (Private)</div>
        <div class="message-content">${escapeHtml(message.content)}</div>
        <div class="message-time">${formatTime(message.created_at)}</div>
    `;
    
    messagesContainer.appendChild(messageDiv);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
    
    console.log('✅ Private message displayed');
}

function displaySystemMessage(text) {
    const messagesContainer = document.getElementById('chatMessages');
    const messageDiv = document.createElement('div');
    
    messageDiv.className = 'message other';
    messageDiv.innerHTML = `
        <div class="message-header">System</div>
        <div class="message-content">${escapeHtml(text)}</div>
        <div class="message-time">${new Date().toLocaleTimeString()}</div>
    `;
    
    messagesContainer.appendChild(messageDiv);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function showError(message) {
    authMessage.className = 'error';
    authMessage.textContent = message;
    console.log('❌ Error:', message);
    setTimeout(() => {
        authMessage.textContent = '';
        authMessage.className = '';
    }, 5000);
}

function showSuccess(message) {
    authMessage.className = 'success';
    authMessage.textContent = message;
    console.log('✅ Success:', message);
    setTimeout(() => {
        authMessage.textContent = '';
        authMessage.className = '';
    }, 3000);
}

function clearMessages() {
    authMessage.textContent = '';
    authMessage.className = '';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatTime(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;
    const oneDay = 24 * 60 * 60 * 1000;
    
    if (diff < oneDay && date.getDate() === now.getDate()) {
        // Same day - show time only
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } else if (diff < oneDay * 7) {
        // Within a week - show day and time
        return date.toLocaleDateString([], { weekday: 'short' }) + ' ' + 
               date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } else {
        // Older - show date and time
        return date.toLocaleDateString() + ' ' + 
               date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
}

// Debug function to check connection status
function checkConnectionStatus() {
    if (socket) {
        console.log('Socket connected:', socket.connected);
        console.log('Socket ID:', socket.id);
        console.log('Current user:', currentUser?.username);
        console.log('Current room:', currentRoom);
        console.log('Private chat with:', currentPrivateUser);
    } else {
        console.log('Socket not initialized');
    }
}

// Make debug function available globally
window.checkConnectionStatus = checkConnectionStatus;

// Auto-reconnect on page visibility change
document.addEventListener('visibilitychange', () => {
    if (!document.hidden && socket && !socket.connected) {
        console.log('🔄 Page became visible, attempting to reconnect...');
        socket.connect();
    }
});

console.log('📱 Chat.js loaded successfully');