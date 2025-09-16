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
        fetch('/api/verify-token', {
            headers: { 'Authorization': `Bearer ${token}` }
        })
        .then(response => {
            if (response.ok) return response.json();
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

    document.getElementById('loginFormElement').addEventListener('submit', handleLogin);
    document.getElementById('registerFormElement').addEventListener('submit', handleRegister);
    logoutBtn.addEventListener('click', handleLogout);

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
        headers: { 'Content-Type': 'application/json' },
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
        headers: { 'Content-Type': 'application/json' },
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
    if (socket) { socket.disconnect(); socket = null; }
    localStorage.removeItem('token');
    currentUser = null;
    currentRoom = 'global';
    currentPrivateUser = null;
    showAuth();
    document.getElementById('chatMessages').innerHTML = `
        <div class="message other">
            <div class="message-header">System</div>
            <div class="message-content">Welcome to the chat! 🎉</div>
            <div class="message-time">Just now</div>
        </div>`;
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
    if (currentUser) currentUsername.textContent = `Welcome, ${currentUser.username}!`;
}

function initializeSocket() {
    console.log('🔌 Initializing socket connection...');
    socket = io({ auth: { token: localStorage.getItem('token') } });

    socket.on('connect', () => {
        console.log('✅ Connected with socket ID:', socket.id);
        joinRoom('global');
    });

    socket.on('user-list', updateUserList);
    socket.on('room-list', updateRoomList);

    socket.on('message', (message) => {
        if (message.room === currentRoom || !currentRoom) displayMessage(message);
    });

    socket.on('private-message', displayPrivateMessage);
    socket.on('user-joined', (data) => displaySystemMessage(`${data.username} joined the room`));

    socket.on('room-deleted', (roomName) => {
        console.log(`🗑️ Room deleted: ${roomName}`);
        displaySystemMessage(`Room "${roomName}" was deleted by the creator/admin.`);
        if (currentRoom === roomName) joinRoom('global');
        socket.emit('get-rooms');
    });

    socket.on('disconnect', () => displaySystemMessage('Disconnected from server. Trying to reconnect...'));
    socket.on('connect_error', (error) => showError('Connection failed. Please refresh the page.'));
    socket.on('error', showError);

    socket.on('reconnect', () => {
        console.log('🔄 Reconnected to server');
        displaySystemMessage('Reconnected to server!');
        if (currentRoom) joinRoom(currentRoom);
    });
}

function sendMessage() {
    const input = document.getElementById('messageInput');
    const message = input.value.trim();
    if (!message) return showError('Cannot send empty message');
    if (!socket || !socket.connected) return showError('Not connected to server');

    console.log('📤 Sending message:', message);
    if (currentPrivateUser) {
        socket.emit('private-message', { to: currentPrivateUser, content: message });
    } else if (currentRoom) {
        socket.emit('message', { room: currentRoom, content: message });
    }
    input.value = '';
    input.focus();
}

function joinRoom(roomName) {
    if (!socket || !socket.connected) return;
    console.log('🏠 Joining room:', roomName);
    currentRoom = roomName;
    currentPrivateUser = null;
    socket.emit('join-room', roomName);

    document.querySelectorAll('.room-list li').forEach(li => li.classList.remove('active'));
    document.querySelectorAll('.room-list li').forEach(li => {
        if (li.textContent.includes(roomName)) li.classList.add('active');
    });

    document.querySelectorAll('.user-list li').forEach(li => li.classList.remove('active'));

    document.getElementById('chatMessages').innerHTML = `
        <div class="message other">
            <div class="message-header">System</div>
            <div class="message-content">Loading messages from ${roomName}...</div>
            <div class="message-time">${new Date().toLocaleTimeString()}</div>
        </div>`;
    document.getElementById('messageInput').focus();
}

function startPrivateChat(username) {
    if (username === currentUser.username) return;
    console.log('💌 Starting private chat with:', username);
    currentPrivateUser = username;
    currentRoom = null;
    document.querySelectorAll('.room-list li').forEach(li => li.classList.remove('active'));
    document.querySelectorAll('.user-list li').forEach(li => {
        li.classList.remove('active');
        if (li.textContent.includes(username)) li.classList.add('active');
    });
    document.getElementById('chatMessages').innerHTML = `
        <div class="message other">
            <div class="message-header">System</div>
            <div class="message-content">Private chat with ${username} 💌</div>
            <div class="message-time">${new Date().toLocaleTimeString()}</div>
        </div>`;
    document.getElementById('messageInput').focus();
}

function createRoom() {
    const roomName = prompt('Enter room name:');
    if (!roomName || !roomName.trim()) return;
    const trimmedName = roomName.trim();
    if (trimmedName.length < 2) return showError('Room name must be at least 2 characters long');
    if (trimmedName.length > 20) return showError('Room name must be less than 20 characters');
    if (!socket || !socket.connected) return showError('Not connected to server');
    console.log('🏗️ Creating room:', trimmedName);
    socket.emit('create-room', trimmedName);
}

// ✅ NEW: Delete Room with Role-based Restriction
function deleteRoom(roomName) {
    if (!socket || !socket.connected) return showError('Not connected to server');
    const confirmDelete = confirm(`Are you sure you want to delete room "${roomName}"?`);
    if (!confirmDelete) return;
    console.log('🗑️ Deleting room:', roomName);
    socket.emit('delete-room', { roomName });
}

function updateUserList(users) {
    const userList = document.getElementById('userList');
    userList.innerHTML = '';
    users.forEach(user => {
        if (user.username !== currentUser.username) {
            const li = document.createElement('li');
            li.innerHTML = `<span class="online-indicator"></span><span>${escapeHtml(user.username)}</span>`;
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
    rooms.forEach(room => {
        const li = document.createElement('li');
        li.classList.add('room-item');
        const canDelete = currentUser.role === 'admin' || room.createdBy === currentUser.username;
        li.innerHTML = `
            <span class="room-name">🏠 ${escapeHtml(room.name)}</span>
            ${canDelete ? `<button class="delete-room-btn" title="Delete Room">🗑️</button>` : ''}
        `;
        li.querySelector('.room-name').addEventListener('click', () => joinRoom(room.name));
        if (canDelete) {
            li.querySelector('.delete-room-btn').addEventListener('click', (e) => {
                e.stopPropagation();
                deleteRoom(room.name);
            });
        }
        if (room.name === currentRoom) li.classList.add('active');
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
    messagesContainer.querySelectorAll('.message .message-content').forEach(msg => {
        if (msg.textContent.includes('Loading messages')) msg.parentElement.remove();
    });
    const messageDiv = document.createElement('div');
    const isOwn = message.sender.username === currentUser.username;
    messageDiv.className = `message ${isOwn ? 'own' : 'other'}`;
    messageDiv.innerHTML = `
        <div class="message-header">${escapeHtml(message.sender.username)}</div>
        <div class="message-content">${escapeHtml(message.content)}</div>
        <div class="message-time">${formatTime(message.created_at)}</div>`;
    messagesContainer.appendChild(messageDiv);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function displayPrivateMessage(message) {
    const messagesContainer = document.getElementById('chatMessages');
    const messageDiv = document.createElement('div');
    const isOwn = message.sender.username === currentUser.username;
    const otherUser = isOwn ? message.recipient.username : message.sender.username;
    messageDiv.className = `message ${isOwn ? 'own' : 'other'}`;
    messageDiv.innerHTML = `
        <div class="message-header">${escapeHtml(message.sender.username)} → ${escapeHtml(otherUser)} (Private)</div>
        <div class="message-content">${escapeHtml(message.content)}</div>
        <div class="message-time">${formatTime(message.created_at)}</div>`;
    messagesContainer.appendChild(messageDiv);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function displaySystemMessage(text) {
    const messagesContainer = document.getElementById('chatMessages');
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message other';
    messageDiv.innerHTML = `
        <div class="message-header">System</div>
        <div class="message-content">${escapeHtml(text)}</div>
        <div class="message-time">${new Date().toLocaleTimeString()}</div>`;
    messagesContainer.appendChild(messageDiv);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function showError(message) {
    authMessage.className = 'error';
    authMessage.textContent = message;
    setTimeout(() => clearMessages(), 5000);
}

function showSuccess(message) {
    authMessage.className = 'success';
    authMessage.textContent = message;
    setTimeout(() => clearMessages(), 3000);
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
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } else if (diff < oneDay * 7) {
        return date.toLocaleDateString([], { weekday: 'short' }) + ' ' +
               date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } else {
        return date.toLocaleDateString() + ' ' +
               date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
}

window.checkConnectionStatus = function() {
    if (socket) {
        console.log('Socket connected:', socket.connected);
        console.log('Socket ID:', socket.id);
        console.log('Current user:', currentUser?.username);
        console.log('Current room:', currentRoom);
        console.log('Private chat with:', currentPrivateUser);
    } else {
        console.log('Socket not initialized');
    }
};

document.addEventListener('visibilitychange', () => {
    if (!document.hidden && socket && !socket.connected) {
        console.log('🔄 Page became visible, attempting to reconnect...');
        socket.connect();
    }
});

console.log('📱 Chat.js loaded successfully');
