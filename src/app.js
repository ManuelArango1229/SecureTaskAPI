'use strict';
const express    = require('express');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

const app    = express();
const PORT   = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET;

if (!SECRET) {
  console.error('FATAL: JWT_SECRET env var not set');
  process.exit(1);
}

app.use(helmet());
app.use(express.json({ limit: '10kb' }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests' },
});
app.use(limiter);

const users = new Map();
const tasks = new Map();
let taskIdCounter = 1;

function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token required' });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

app.get('/', (_req, res) =>
  res.json({ name: 'SecureTaskAPI', version: '1.0.0', status: 'ok' })
);

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

app.post('/auth/register',
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });
    const { email, password } = req.body;
    if (users.has(email))
      return res.status(409).json({ error: 'User exists' });
    const hash = await bcrypt.hash(password, 12);
    users.set(email, { email, hash });
    res.status(201).json({ message: 'Registered' });
  }
);

app.post('/auth/login',
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });
    const { email, password } = req.body;
    const user = users.get(email);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, user.hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ email }, SECRET, { expiresIn: '1h' });
    res.json({ token });
  }
);

app.get('/tasks', authenticate, (req, res) => {
  const mine = [...tasks.values()].filter(t => t.owner === req.user.email);
  res.json(mine);
});

app.post('/tasks', authenticate,
  body('title').notEmpty().trim().escape(),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });
    const task = {
      id: taskIdCounter++,
      title: req.body.title,
      owner: req.user.email,
    };
    tasks.set(task.id, task);
    res.status(201).json(task);
  }
);

app.delete('/tasks/:id', authenticate, (req, res) => {
  const task = tasks.get(Number(req.params.id));
  if (!task || task.owner !== req.user.email)
    return res.status(404).json({ error: 'Not found' });
  tasks.delete(task.id);
  res.json({ message: 'Deleted' });
});

app.listen(PORT, () => console.log(`SecureTaskAPI listening on ${PORT}`));