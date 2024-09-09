const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const path = require('path');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json()); // For parsing application/json

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/mydatabase', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// Define User schema and model
const saltRounds = 10;

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  lastLogin: Date,
});

// Hash password before saving user
UserSchema.pre('save', function(next) {
  if (this.isModified('password')) {
    bcrypt.hash(this.password, saltRounds, (err, hash) => {
      if (err) return next(err);
      this.password = hash;
      next();
    });
  } else {
    next();
  }
});

const User = mongoose.model('User', UserSchema);

// Signup route
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    const existingUser = await User.findOne({ username });

    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const newUser = new User({ username, password });
    await newUser.save();

    res.status(201).json({ message: 'User created successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Login route with password verification
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    user.lastLogin = new Date();
    await user.save();

    res.status(200).json({ message: 'Login successful', user });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Serve static files from the 'public' directory (for example, HTML files)
app.use(express.static(path.join(__dirname, 'public')));

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
