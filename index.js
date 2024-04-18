require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const fs = require('fs');

const User = require('./models/User');
const Post = require('./models/Post');

const uploadMiddleware = multer({ dest: 'uploads/' });
const secret = process.env.SECRET;

const app = express();

app.use(cors({
  origin: process.env.CORS_ORIGIN,
  credentials: true,
}));

app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', process.env.CORS_ORIGIN);
  res.header('Access-Control-Allow-Methods', 'POST');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.sendStatus(200);
});


app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static(__dirname + '/uploads'));




mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log('MongoDB connected');
}).catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1); // Terminate the application if MongoDB connection fails
});


app.post('/register', async (req, res, next) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const userDoc = await User.create({ username, password: hashedPassword });
    res.json(userDoc);
    res.header('Access-Control-Allow-Origin', process.env.CORS_ORIGIN);
  } catch (error) {
    console.error('Error creating user:', error);
    next(error); // Pass error to error handling middleware
  }
});

app.post('/login', async (req, res, next) => {
  const { username, password } = req.body;
  try {
    const userDoc = await User.findOne({ username });
    const passOk = userDoc && bcrypt.compareSync(password, userDoc.password);
    if (!passOk) {
      return res.status(400).json({ message: 'Invalid username or password' });
    }
    jwt.sign({ username, id: userDoc._id }, secret, {}, (err, token) => {
      if (err) {
        console.error('Error signing token:', err);
        next(err); // Pass error to error handling middleware
      }
      res.cookie('token', token).json({ id: userDoc._id, username });
    });
    res.header('Access-Control-Allow-Origin', process.env.CORS_ORIGIN);
  } catch (error) {
    console.error('Error logging in:', error);
    next(error); // Pass error to error handling middleware
  }
});

app.get('/profile', (req, res, next) => {
  const { token } = req.cookies;
  jwt.verify(token, secret, {}, (err, info) => {
    if (err) {
      console.error('Error decoding token:', err);
      res.clearCookie('token');
      return res.status(401).json({ message: 'Unauthorized', error: err.message });
    }
    res.header('Access-Control-Allow-Origin', process.env.CORS_ORIGIN);
    res.json(info);
  });
});

app.post('/logout', (req, res, next) => {
  res.clearCookie('token').json('ok');
});

app.post('/post', uploadMiddleware.single('file'), async(req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const { originalname, path } = req.file;
    const parts = originalname.split('.');
    const ext = parts[parts.length - 1];
    const newPath = path + '.' + ext;
    fs.renameSync(path, path + '.' + ext);

    const {token} = req.cookies;
    jwt.verify(token, secret, {}, async (err, info) => {
      if (err) {
        console.error('Error decoding token:', err);
        return res.status(401).json({ message: 'Unauthorized', error: err.message });
      }
      const {title, summary, content} = req.body;
      const postDoc = await Post.create({
        title,
        summary,
        content,
        cover: newPath,
        author:info.id,
      });
      res.json(postDoc)
    });

  } catch (error) {
    console.error('Error uploading file:', error);
    next(error); // Pass error to error handling middleware
  }
});

app.put('/post', uploadMiddleware.single('file'), async (req, res, next) => {
  let newPath = null;
  if (req.file) {
    const { originalname, path } = req.file;
    const parts = originalname.split('.');
    const ext = parts[parts.length - 1];
    newPath = path + '.' + ext;
    fs.renameSync(path, newPath);
  }

  const { token } = req.cookies;
  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) {
      console.error('Error decoding token:', err);
      return res.status(401).json({ message: 'Unauthorized', error: err.message });
    }
    const { id, title, summary, content } = req.body;
    try {
      const postDoc = await Post.findById(id);
      if (!postDoc) {
        return res.status(404).json('Post not found');
      }
      if (postDoc.author.toString() !== info.id) {
        return res.status(401).json('You are not the author');
      }
      postDoc.title = title;
      postDoc.summary = summary;
      postDoc.content = content;
      postDoc.cover = newPath ? newPath : postDoc.cover;
      await postDoc.save();
      res.json(postDoc);
    } catch (error) {
      console.error('Error updating post:', error);
      next(error); // Pass error to error handling middleware
    }
  });
});


app.get('/posts', async (req, res, next) => {
  try {
    const posts = await Post.find().populate('author', ['username']).sort({createdAt: -1}).limit(20);
    res.header('Access-Control-Allow-Origin', process.env.CORS_ORIGIN);
    res.json(posts);
  } catch (error) {
    console.error('Error retrieving posts:', error);
    next(error); // Pass error to error handling middleware
  }
});


app.get('/post/:id', async(req, res, next) => {
  const {id} = req.params
  try {
    const postDoc = await Post.findById(id).populate('author', ['username']);
    if (!postDoc) {
      return res.status(404).json('Post not found');
    }
    res.json(postDoc);
  } catch (error) {
    console.error('Error retrieving post:', error);
    next(error); // Pass error to error handling middleware
  }
});

const PORT = process.env.PORT || 4040;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
