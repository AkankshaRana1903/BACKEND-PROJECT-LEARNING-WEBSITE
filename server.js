const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3001;
const JWT_SECRET = 'your_jwt_secret_key'; // In production, use env variable

app.use(cors());
app.use(bodyParser.json());

// Root route to confirm server is running
app.get('/', (req, res) => {
  res.send('Authentication API server is running.');
});

// Path to users.json file
const usersFilePath = path.join(__dirname, 'users.json');

// Function to read users from JSON file
function readUsers() {
  try {
    const data = fs.readFileSync(usersFilePath, 'utf8');
    const users = JSON.parse(data);
    console.log('Read users:', users);
    return users;
  } catch (err) {
    console.error('Error reading users:', err);
    return [];
  }
}

// Function to write users to JSON file
function writeUsers(users) {
  fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));
  console.log('Updated users:', users);
}


const roles = {
  admin: {
    can: ['manage_users', 'manage_content', 'review_content', 'oversee_subscriptions'],
  },
  educator: {
    can: ['create_courses', 'manage_courses', 'respond_queries', 'track_progress'],
  },
  learner: {
    can: ['access_courses', 'post_reviews', 'delete_own_reviews', 'participate_discussions'],
  },
  guest: {
    can: ['view_content'],
  },
};

// Middleware to authenticate JWT token and set req.user
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Middleware to authorize based on role and permission
function authorize(permission) {
  return (req, res, next) => {
    const userRole = req.user.role;
    if (roles[userRole] && roles[userRole].can.includes(permission)) {
      next();
    } else {
      res.status(403).json({ message: 'Forbidden: insufficient permissions' });
    }
  };
}

// Register route
app.post('/api/register', async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) {
    return res.status(400).json({ message: 'Username, password and role are required' });
  }
  if (!roles[role]) {
    return res.status(400).json({ message: 'Invalid role' });
  }
  const users = readUsers();
  const existingUser = users.find(u => u.username === username);
  if (existingUser) {
    return res.status(409).json({ message: 'Username already exists' });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { id: users.length + 1, username, password: hashedPassword, role };
  users.push(newUser);
  writeUsers(users);
  res.status(201).json({ message: 'User registered successfully' });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const users = readUsers();
  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  const token = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token, role: user.role });
});

// Example protected route for Admin
app.get('/api/admin/dashboard', authenticateToken, authorize('manage_users'), (req, res) => {
  res.json({ message: 'Welcome to Admin dashboard' });
});

// Admin routes
app.get('/api/admin/users', authenticateToken, authorize('manage_users'), (req, res) => {
  const users = readUsers();
  res.json(users);
});

app.post('/api/admin/users', authenticateToken, authorize('manage_users'), (req, res) => {
  const users = readUsers();
  const newUser = req.body;
  newUser.id = users.length + 1;
  users.push(newUser);
  writeUsers(users);
  res.status(201).json(newUser);
});

app.put('/api/admin/users/:id', authenticateToken, authorize('manage_users'), (req, res) => {
  const users = readUsers();
  const userId = parseInt(req.params.id);
  const index = users.findIndex(u => u.id === userId);
  if (index === -1) {
    return res.status(404).json({ message: 'User not found' });
  }
  users[index] = { ...users[index], ...req.body };
  writeUsers(users);
  res.json(users[index]);
});

// Example protected route for Educator
app.get('/api/educator/courses', authenticateToken, authorize('create_courses'), (req, res) => {
  res.json({ message: 'Educator courses management' });
});

// Educator routes
app.post('/api/educator/courses', authenticateToken, authorize('create_courses'), (req, res) => {
  // Placeholder: Add course creation logic here
  res.status(201).json({ message: 'Course created' });
});

app.put('/api/educator/courses/:id', authenticateToken, authorize('manage_courses'), (req, res) => {
  // Placeholder: Add course update logic here
  res.json({ message: `Course ${req.params.id} updated` });
});

// Example protected route for Learner
app.get('/api/learner/courses', authenticateToken, authorize('access_courses'), (req, res) => {
  res.json({ message: 'Learner enrolled courses' });
});

// Learner routes
app.post('/api/learner/courses', authenticateToken, authorize('access_courses'), (req, res) => {
  // Placeholder: Add course enrollment logic here
  res.status(201).json({ message: 'Enrolled in course' });
});

app.put('/api/learner/profile', authenticateToken, authorize('access_courses'), (req, res) => {
  const users = readUsers();
  const username = req.user.username;
  const index = users.findIndex(u => u.username === username);
  if (index === -1) {
    return res.status(404).json({ message: 'User not found' });
  }
  users[index] = { ...users[index], ...req.body };
  writeUsers(users);
  res.json(users[index]);
});

// Public route for guests
app.get('/api/public/content', (req, res) => {
  res.json({ message: 'Public content for guests' });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
