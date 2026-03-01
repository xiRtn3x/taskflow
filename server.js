require('dotenv').config();
const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const MONGO_URI = process.env.MONGO_URI;
const DB_NAME = 'taskflow';
const ADMIN_PIN = process.env.ADMIN_PIN || '0000';

if (!MONGO_URI) {
  console.error('\n❌ MONGO_URI fehlt in .env\n');
  process.exit(1);
}

let db;
async function connectDB() {
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  db = client.db(DB_NAME);
  console.log('✅ MongoDB verbunden');
}

function genToken() { return crypto.randomBytes(32).toString('hex'); }

async function auth(req, res, next) {
  const token = req.headers['x-token'];
  if (!token) return res.status(401).json({ error: 'Kein Token' });
  const user = await db.collection('users').findOne({ token });
  if (!user) return res.status(401).json({ error: 'Ungültiger Token' });
  req.user = user;
  next();
}

// ═══════════════════════════════════════════════════════
// ADMIN
// ═══════════════════════════════════════════════════════
app.post('/api/admin/verify', auth, async (req, res) => {
  const { pin } = req.body;
  if (pin !== ADMIN_PIN) return res.status(403).json({ error: 'Falscher PIN' });
  res.json({ ok: true });
});

app.get('/api/admin/data', auth, async (req, res) => {
  const { pin } = req.query;
  if (pin !== ADMIN_PIN) return res.status(403).json({ error: 'Kein Zugriff' });
  try {
    const users = await db.collection('users').find({}).project({ token: 0 }).toArray();
    const groups = await db.collection('groups').find({}).toArray();
    const tasks = await db.collection('tasks').find({}).toArray();
    const userList = users.map(u => {
      const g = groups.find(g => g._id.toString() === u.groupId);
      const taskCount = tasks.filter(t => t.assignee === u._id.toString() || (t.ownerId === u._id.toString() && !t.groupId)).length;
      return { ...u, _id: u._id.toString(), groupName: g?.name || (u.solo ? 'Solo' : '–'), groupCode: g?.inviteCode || '–', taskCount, createdAt: u.createdAt };
    });
    res.json({ users: userList, groups: groups.map(g => ({ ...g, _id: g._id.toString() })), totalTasks: tasks.length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════
// USERS
// ═══════════════════════════════════════════════════════
app.post('/api/users/login', async (req, res) => {
  try {
    const { username } = req.body;
    if (!username?.trim()) return res.status(400).json({ error: 'Name fehlt' });
    let user = await db.collection('users').findOne({ name: username.trim() });
    if (!user) {
      const token = genToken();
      const result = await db.collection('users').insertOne({
        name: username.trim(), color: '#6C63FF', photo: null, token,
        groupId: null, solo: false, colorOverrides: {}, notifications: [],
        theme: 'light', createdAt: new Date()
      });
      user = await db.collection('users').findOne({ _id: result.insertedId });
    }
    res.json({ token: user.token, userId: user._id.toString(), needsSetup: !user.groupId && !user.solo });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/users/me', auth, async (req, res) => {
  const { token: _t, ...user } = req.user;
  res.json({ ...user, _id: user._id.toString() });
});

app.patch('/api/users/me', auth, async (req, res) => {
  try {
    const allowed = ['name','color','photo','colorOverrides','solo','theme'];
    const update = {};
    allowed.forEach(k => { if (req.body[k] !== undefined) update[k] = req.body[k]; });
    await db.collection('users').updateOne({ _id: req.user._id }, { $set: update });
    const updated = await db.collection('users').findOne({ _id: req.user._id });
    const { token: _t, ...safe } = updated;
    res.json({ ...safe, _id: safe._id.toString() });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/users/me', auth, async (req, res) => {
  try {
    const u = req.user;
    if (u.groupId) {
      const group = await db.collection('groups').findOne({ _id: new ObjectId(u.groupId) });
      if (group && group.creatorId === u._id.toString() && group.memberIds.length > 1)
        return res.status(400).json({ error: 'Gruppe erst löschen.' });
      if (group) await db.collection('groups').updateOne({ _id: new ObjectId(u.groupId) }, { $pull: { memberIds: u._id.toString() } });
    }
    await db.collection('tasks').deleteMany({ assignee: u._id.toString(), groupId: u.groupId || null });
    await db.collection('users').deleteOne({ _id: u._id });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/users', auth, async (req, res) => {
  try {
    let users = [];
    if (req.user.groupId) {
      const group = await db.collection('groups').findOne({ _id: new ObjectId(req.user.groupId) });
      if (group) users = await db.collection('users').find({ _id: { $in: group.memberIds.map(id => new ObjectId(id)) } }).project({ token: 0 }).toArray();
    } else {
      users = [{ ...req.user }];
    }
    res.json(users.map(u => ({ ...u, _id: u._id.toString(), token: undefined })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/users/notifications', auth, async (req, res) => {
  res.json(req.user.notifications || []);
});

app.delete('/api/users/notifications', auth, async (req, res) => {
  await db.collection('users').updateOne({ _id: req.user._id }, { $set: { notifications: [] } });
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════
// GROUPS
// ═══════════════════════════════════════════════════════
app.post('/api/groups', auth, async (req, res) => {
  try {
    const { name, photo } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: 'Name fehlt' });
    const result = await db.collection('groups').insertOne({
      name: name.trim(), photo: photo || null,
      creatorId: req.user._id.toString(),
      memberIds: [req.user._id.toString()],
      inviteCode: genToken().slice(0,8).toUpperCase(),
      createdAt: new Date()
    });
    const group = await db.collection('groups').findOne({ _id: result.insertedId });
    await db.collection('users').updateOne({ _id: req.user._id }, { $set: { groupId: result.insertedId.toString(), solo: false } });
    res.json({ ...group, _id: group._id.toString() });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/groups/join', auth, async (req, res) => {
  try {
    const { inviteCode } = req.body;
    const group = await db.collection('groups').findOne({ inviteCode: inviteCode?.toUpperCase() });
    if (!group) return res.status(404).json({ error: 'Gruppe nicht gefunden' });
    const uid = req.user._id.toString();
    if (!group.memberIds.includes(uid))
      await db.collection('groups').updateOne({ _id: group._id }, { $push: { memberIds: uid } });
    await db.collection('users').updateOne({ _id: req.user._id }, { $set: { groupId: group._id.toString(), solo: false } });
    res.json({ ...group, _id: group._id.toString() });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/groups/mine', auth, async (req, res) => {
  try {
    if (!req.user.groupId) return res.json(null);
    const group = await db.collection('groups').findOne({ _id: new ObjectId(req.user.groupId) });
    res.json(group ? { ...group, _id: group._id.toString() } : null);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/groups/mine', auth, async (req, res) => {
  try {
    const group = await db.collection('groups').findOne({ _id: new ObjectId(req.user.groupId) });
    if (!group || group.creatorId !== req.user._id.toString()) return res.status(403).json({ error: 'Kein Zugriff' });
    const { name, photo } = req.body;
    const update = {};
    if (name) update.name = name.trim();
    if (photo !== undefined) update.photo = photo;
    await db.collection('groups').updateOne({ _id: group._id }, { $set: update });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/groups/mine', auth, async (req, res) => {
  try {
    const group = await db.collection('groups').findOne({ _id: new ObjectId(req.user.groupId) });
    if (!group || group.creatorId !== req.user._id.toString()) return res.status(403).json({ error: 'Kein Zugriff' });
    await db.collection('users').updateMany({ _id: { $in: group.memberIds.map(id => new ObjectId(id)) } }, { $set: { groupId: null } });
    await db.collection('tasks').deleteMany({ groupId: group._id.toString() });
    await db.collection('groups').deleteOne({ _id: group._id });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/groups/leave', auth, async (req, res) => {
  try {
    const u = req.user;
    if (!u.groupId) return res.status(400).json({ error: 'Nicht in Gruppe' });
    const group = await db.collection('groups').findOne({ _id: new ObjectId(u.groupId) });
    if (group?.creatorId === u._id.toString() && group.memberIds.length > 1)
      return res.status(400).json({ error: 'Zuerst Gruppe löschen.' });
    await db.collection('groups').updateOne({ _id: new ObjectId(u.groupId) }, { $pull: { memberIds: u._id.toString() } });
    await db.collection('users').updateOne({ _id: u._id }, { $set: { groupId: null } });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════
// TASKS
// ═══════════════════════════════════════════════════════
function scope(user) {
  return user.groupId ? { groupId: user.groupId } : { groupId: null, ownerId: user._id.toString() };
}

app.get('/api/tasks', auth, async (req, res) => {
  try {
    const tasks = await db.collection('tasks').find(scope(req.user)).toArray();
    res.json(tasks.map(t => ({ ...t, _id: t._id.toString() })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/tasks', auth, async (req, res) => {
  try {
    const task = { ...req.body, ...scope(req.user), creatorId: req.user._id.toString(), createdAt: new Date() };
    const result = await db.collection('tasks').insertOne(task);
    const assignee = task.assignee;
    if (assignee && assignee !== 'all' && assignee !== req.user._id.toString()) {
      await db.collection('users').updateOne({ _id: new ObjectId(assignee) }, { $push: { notifications: {
        id: genToken().slice(0,8), type: 'task_assigned',
        text: `📋 ${req.user.name} hat dir eine neue Aufgabe zugewiesen: „${task.title}"`,
        taskId: result.insertedId.toString(), createdAt: new Date()
      }}});
    }
    res.json({ ...task, _id: result.insertedId.toString() });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/tasks/:id', auth, async (req, res) => {
  try {
    const task = await db.collection('tasks').findOne({ _id: new ObjectId(req.params.id) });
    if (!task) return res.status(404).json({ error: 'Nicht gefunden' });
    const update = { ...req.body }; delete update._id;
    await db.collection('tasks').updateOne({ _id: new ObjectId(req.params.id) }, { $set: update });
    if (update.done === true && task.creatorId && task.creatorId !== req.user._id.toString()) {
      await db.collection('users').updateOne({ _id: new ObjectId(task.creatorId) }, { $push: { notifications: {
        id: genToken().slice(0,8), type: 'task_done',
        text: `✅ ${req.user.name} hat „${task.title}" erledigt!`,
        taskId: req.params.id, createdAt: new Date()
      }}});
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/tasks/:id', auth, async (req, res) => {
  try {
    await db.collection('tasks').deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════
// APPSTATE (pool, cats, settings)
// ═══════════════════════════════════════════════════════
app.get('/api/appstate', auth, async (req, res) => {
  try {
    const key = req.user.groupId || req.user._id.toString();
    const doc = await db.collection('appstate').findOne({ _id: key });
    if (!doc) return res.json({});
    const { _id, ...state } = doc;
    res.json(state);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/appstate', auth, async (req, res) => {
  try {
    const key = req.user.groupId || req.user._id.toString();
    await db.collection('appstate').replaceOne({ _id: key }, { _id: key, ...req.body }, { upsert: true });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════
// POLLING
// ═══════════════════════════════════════════════════════
app.get('/api/poll', auth, async (req, res) => {
  try {
    const tasks = await db.collection('tasks').find(scope(req.user)).toArray();
    const users = await db.collection('users')
      .find(req.user.groupId ? { groupId: req.user.groupId } : { _id: req.user._id })
      .project({ token: 0, notifications: 0 }).toArray();
    const hash = crypto.createHash('md5').update(JSON.stringify(tasks)+JSON.stringify(users)).digest('hex');
    const notifs = req.user.notifications || [];
    res.json({ hash, hasNotifications: notifs.length > 0 });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════
// FALLBACK
// ═══════════════════════════════════════════════════════
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3000;
connectDB().then(() => app.listen(PORT, () => console.log(`🚀 Server läuft auf http://localhost:${PORT}`))).catch(err => { console.error('❌', err.message); process.exit(1); });
