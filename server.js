require('dotenv').config();
const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const MONGO_URI = process.env.MONGO_URI;
const DB_NAME = 'taskflow';
const ADMIN_PIN = process.env.ADMIN_PIN || '0000';

if (!MONGO_URI) { console.error('\n❌ MONGO_URI fehlt\n'); process.exit(1); }

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

// Scope für Tasks (Gruppe oder Solo-User)
function scope(user) {
  return user.groupId
    ? { groupId: user.groupId }
    : { groupId: null, ownerId: user._id.toString() };
}

// Scope für Shopping (Gruppe oder Solo-User)
function shopScope(user) {
  return user.groupId
    ? { groupId: user.groupId }
    : { groupId: null, userId: user._id.toString() };
}

// Hilfsfunktion: hat ein Artikel eine Wiederholung?
function isRepeating(repeat) {
  if (!repeat) return false;
  if (typeof repeat === 'string') return repeat !== '';
  return repeat.type && repeat.type !== 'none';
}

// ── CHANGELOG ────────────────────────────────────
app.get('/api/changelog', (req, res) => {
  try {
    const p = path.join(__dirname, 'public', 'changelog.json');
    if (fs.existsSync(p)) res.json(JSON.parse(fs.readFileSync(p, 'utf8')));
    else res.json({ version: '1.0', entries: [] });
  } catch(e) { res.json({ version: '1.0', entries: [] }); }
});

// ── ADMIN ─────────────────────────────────────────
app.post('/api/admin/verify', auth, async (req, res) => {
  if (req.body.pin !== ADMIN_PIN) return res.status(403).json({ error: 'Falscher PIN' });
  res.json({ ok: true });
});

app.get('/api/admin/data', auth, async (req, res) => {
  if (req.query.pin !== ADMIN_PIN) return res.status(403).json({ error: 'Kein Zugriff' });
  try {
    const users = await db.collection('users').find({}).project({ token: 0 }).toArray();
    const groups = await db.collection('groups').find({}).toArray();
    const tasks = await db.collection('tasks').find({}).toArray();
    const userList = users.map(u => {
      const g = groups.find(g => g._id.toString() === u.groupId);
      return {
        ...u, _id: u._id.toString(),
        groupName: g?.name || (u.solo ? 'Solo' : '–'),
        groupCode: g?.inviteCode || '–',
        groupId: u.groupId || null,
        taskCount: tasks.filter(t => t.assignee === u._id.toString()).length,
        createdAt: u.createdAt
      };
    });
    res.json({
      users: userList,
      groups: groups.map(g => ({
        ...g, _id: g._id.toString(),
        memberCount: g.memberIds?.length || 0,
        taskCount: tasks.filter(t => t.groupId === g._id.toString()).length
      })),
      totalTasks: tasks.length
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/user/:id', auth, async (req, res) => {
  if (req.query.pin !== ADMIN_PIN) return res.status(403).json({ error: 'Kein Zugriff' });
  try {
    const uid = req.params.id;
    const user = await db.collection('users').findOne({ _id: new ObjectId(uid) });
    if (!user) return res.status(404).json({ error: 'Nicht gefunden' });
    if (user.groupId) {
      await db.collection('groups').updateOne(
        { _id: new ObjectId(user.groupId) },
        { $pull: { memberIds: uid } }
      );
    }
    await db.collection('tasks').deleteMany({ assignee: uid });
    await db.collection('users').deleteOne({ _id: new ObjectId(uid) });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/group/:id', auth, async (req, res) => {
  if (req.query.pin !== ADMIN_PIN) return res.status(403).json({ error: 'Kein Zugriff' });
  try {
    const gid = req.params.id;
    await db.collection('users').updateMany({ groupId: gid }, { $set: { groupId: null } });
    await db.collection('tasks').deleteMany({ groupId: gid });
    await db.collection('appstate').deleteOne({ _id: gid });
    await db.collection('groups').deleteOne({ _id: new ObjectId(gid) });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── USERS ─────────────────────────────────────────
app.post('/api/users/login', async (req, res) => {
  try {
    const { username } = req.body;
    if (!username?.trim()) return res.status(400).json({ error: 'Name fehlt' });
    let user = await db.collection('users').findOne({ name: username.trim() });
    if (!user) {
      const token = genToken();
      const r = await db.collection('users').insertOne({
        name: username.trim(), color: '#5B5BD6', photo: null, token,
        groupId: null, solo: false, colorOverrides: {}, notifications: [],
        theme: '', lastVisit: new Date(), createdAt: new Date()
      });
      user = await db.collection('users').findOne({ _id: r.insertedId });
    }
    res.json({ token: user.token, userId: user._id.toString() });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/users/me', auth, async (req, res) => {
  const { token: _t, ...user } = req.user;
  await db.collection('users').updateOne({ _id: req.user._id }, { $set: { lastVisit: new Date() } });
  res.json({ ...user, _id: user._id.toString() });
});

app.patch('/api/users/me', auth, async (req, res) => {
  try {
    const allowed = ['name','color','photo','colorOverrides','solo','theme','lastVisit'];
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
      const g = await db.collection('groups').findOne({ _id: new ObjectId(u.groupId) });
      if (g?.creatorId === u._id.toString() && g.memberIds.length > 1)
        return res.status(400).json({ error: 'Gruppe erst löschen.' });
      if (g) await db.collection('groups').updateOne(
        { _id: new ObjectId(u.groupId) },
        { $pull: { memberIds: u._id.toString() } }
      );
    }
    await db.collection('tasks').deleteMany({ assignee: u._id.toString() });
    await db.collection('users').deleteOne({ _id: u._id });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/users', auth, async (req, res) => {
  try {
    let list = [];
    if (req.user.groupId) {
      const g = await db.collection('groups').findOne({ _id: new ObjectId(req.user.groupId) });
      if (g) list = await db.collection('users')
        .find({ _id: { $in: g.memberIds.map(id => new ObjectId(id)) } })
        .project({ token: 0 })
        .toArray();
    } else {
      list = [{ ...req.user }];
    }
    res.json(list.map(u => ({ ...u, _id: u._id.toString(), token: undefined })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/users/notifications', auth, async (req, res) => res.json(req.user.notifications || []));

app.delete('/api/users/notifications', auth, async (req, res) => {
  await db.collection('users').updateOne({ _id: req.user._id }, { $set: { notifications: [] } });
  res.json({ ok: true });
});

app.post('/api/users/:id/notify', auth, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: 'Nachricht fehlt' });
    await db.collection('users').updateOne(
      { _id: new ObjectId(req.params.id) },
      { $push: { notifications: {
        id: genToken().slice(0,8), type: 'info',
        text: message, createdAt: new Date()
      }}}
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── GROUPS ────────────────────────────────────────
app.post('/api/groups', auth, async (req, res) => {
  try {
    const { name, photo } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: 'Name fehlt' });
    const r = await db.collection('groups').insertOne({
      name: name.trim(), photo: photo || null,
      creatorId: req.user._id.toString(),
      memberIds: [req.user._id.toString()],
      inviteCode: genToken().slice(0,8).toUpperCase(),
      createdAt: new Date()
    });
    const g = await db.collection('groups').findOne({ _id: r.insertedId });
    await db.collection('users').updateOne(
      { _id: req.user._id },
      { $set: { groupId: r.insertedId.toString(), solo: false } }
    );
    res.json({ ...g, _id: g._id.toString() });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/groups/join', auth, async (req, res) => {
  try {
    const g = await db.collection('groups').findOne({ inviteCode: req.body.inviteCode?.toUpperCase() });
    if (!g) return res.status(404).json({ error: 'Gruppe nicht gefunden' });
    const uid = req.user._id.toString();
    if (!g.memberIds.includes(uid))
      await db.collection('groups').updateOne({ _id: g._id }, { $push: { memberIds: uid } });
    await db.collection('users').updateOne(
      { _id: req.user._id },
      { $set: { groupId: g._id.toString(), solo: false } }
    );
    res.json({ ...g, _id: g._id.toString() });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/groups/mine', auth, async (req, res) => {
  try {
    if (!req.user.groupId) return res.json(null);
    const g = await db.collection('groups').findOne({ _id: new ObjectId(req.user.groupId) });
    res.json(g ? { ...g, _id: g._id.toString() } : null);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/groups/mine', auth, async (req, res) => {
  try {
    const g = await db.collection('groups').findOne({ _id: new ObjectId(req.user.groupId) });
    if (!g || g.creatorId !== req.user._id.toString())
      return res.status(403).json({ error: 'Kein Zugriff' });
    const update = {};
    if (req.body.name) update.name = req.body.name.trim();
    if (req.body.photo !== undefined) update.photo = req.body.photo;
    await db.collection('groups').updateOne({ _id: g._id }, { $set: update });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/groups/mine', auth, async (req, res) => {
  try {
    const g = await db.collection('groups').findOne({ _id: new ObjectId(req.user.groupId) });
    if (!g || g.creatorId !== req.user._id.toString())
      return res.status(403).json({ error: 'Kein Zugriff' });
    await db.collection('users').updateMany(
      { _id: { $in: g.memberIds.map(id => new ObjectId(id)) } },
      { $set: { groupId: null } }
    );
    await db.collection('tasks').deleteMany({ groupId: g._id.toString() });
    await db.collection('appstate').deleteOne({ _id: g._id.toString() });
    await db.collection('shopping').deleteMany({ groupId: g._id.toString() });
    await db.collection('mealplans').deleteOne({ groupId: g._id.toString() });
    await db.collection('recipes').deleteMany({ groupId: g._id.toString() });
    await db.collection('groups').deleteOne({ _id: g._id });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/groups/leave', auth, async (req, res) => {
  try {
    const u = req.user;
    if (!u.groupId) return res.status(400).json({ error: 'Nicht in Gruppe' });
    const g = await db.collection('groups').findOne({ _id: new ObjectId(u.groupId) });
    if (g?.creatorId === u._id.toString() && g.memberIds.length > 1)
      return res.status(400).json({ error: 'Zuerst Gruppe löschen.' });
    await db.collection('groups').updateOne(
      { _id: new ObjectId(u.groupId) },
      { $pull: { memberIds: u._id.toString() } }
    );
    await db.collection('users').updateOne({ _id: u._id }, { $set: { groupId: null } });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── TASKS ─────────────────────────────────────────
app.get('/api/tasks', auth, async (req, res) => {
  try {
    const tasks = await db.collection('tasks').find(scope(req.user)).toArray();
    res.json(tasks.map(t => ({ ...t, _id: t._id.toString() })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/tasks', auth, async (req, res) => {
  try {
    const task = { ...req.body, ...scope(req.user), creatorId: req.user._id.toString(), createdAt: new Date() };
    const r = await db.collection('tasks').insertOne(task);
    const assignee = task.assignee;
    if (assignee && assignee !== 'all' && assignee !== req.user._id.toString()) {
      await db.collection('users').updateOne(
        { _id: new ObjectId(assignee) },
        { $push: { notifications: {
          id: genToken().slice(0,8), type: 'task_assigned',
          text: `${req.user.name} hat dir eine neue Aufgabe zugewiesen: „${task.title}"`,
          taskId: r.insertedId.toString(), createdAt: new Date()
        }}}
      );
    }
    res.json({ ...task, _id: r.insertedId.toString() });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/tasks/:id', auth, async (req, res) => {
  try {
    const task = await db.collection('tasks').findOne({ _id: new ObjectId(req.params.id) });
    if (!task) return res.status(404).json({ error: 'Nicht gefunden' });
    const update = { ...req.body }; delete update._id;
    await db.collection('tasks').updateOne({ _id: new ObjectId(req.params.id) }, { $set: update });
    if (update.done === true && task.creatorId && task.creatorId !== req.user._id.toString()) {
      await db.collection('users').updateOne(
        { _id: new ObjectId(task.creatorId) },
        { $push: { notifications: {
          id: genToken().slice(0,8), type: 'task_done',
          text: `${req.user.name} hat „${task.title}" erledigt!`,
          taskId: req.params.id, createdAt: new Date()
        }}}
      );
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

// ── APPSTATE ──────────────────────────────────────
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
    await db.collection('appstate').replaceOne(
      { _id: key },
      { _id: key, ...req.body },
      { upsert: true }
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── SHOPPING ──────────────────────────────────────

app.get('/api/shopping', auth, async (req, res) => {
  try {
    const items = await db.collection('shopping')
      .find(shopScope(req.user))
      .sort({ createdAt: 1 })
      .toArray();
    res.json(items.map(i => ({ ...i, _id: i._id.toString() })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── FIX: photos-Array und selectedPhotoIndex werden jetzt gespeichert ──
app.post('/api/shopping', auth, async (req, res) => {
  try {
    const { title, category, qty, price, comment, repeat, photo, photos, selectedPhotoIndex } = req.body;
    if (!title?.trim()) return res.status(400).json({ error: 'Titel fehlt' });
    const doc = {
      ...shopScope(req.user),
      title:              title.trim(),
      category:           category || 'Sonstiges',
      qty:                qty      || '',
      price:              price    || '',
      comment:            comment  || '',
      repeat:             repeat   || null,
      photo:              photo    || null,
      photos:             Array.isArray(photos) ? photos : (photo ? [photo] : []),
      selectedPhotoIndex: typeof selectedPhotoIndex === 'number' ? selectedPhotoIndex : null,
      checked:            false,
      createdAt:          new Date(),
    };
    const r = await db.collection('shopping').insertOne(doc);
    res.status(201).json({ ...doc, _id: r.insertedId.toString() });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── FIX: photos und selectedPhotoIndex in der allowed-Liste ergänzt ──
app.patch('/api/shopping/:id', auth, async (req, res) => {
  try {
    const filter = { _id: new ObjectId(req.params.id), ...shopScope(req.user) };
    const allowed = ['title','category','qty','price','comment','repeat','photo','photos','selectedPhotoIndex','checked'];
    const update = {};
    allowed.forEach(f => { if (req.body[f] !== undefined) update[f] = req.body[f]; });
    const r = await db.collection('shopping').findOneAndUpdate(
      filter,
      { $set: update },
      { returnDocument: 'after' }
    );
    if (!r) return res.status(404).json({ error: 'Nicht gefunden' });
    res.json({ ...r, _id: r._id.toString() });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/shopping/:id', auth, async (req, res) => {
  try {
    await db.collection('shopping').deleteOne({
      _id: new ObjectId(req.params.id),
      ...shopScope(req.user)
    });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/shopping/finish', auth, async (req, res) => {
  try {
    const { resetRepeating } = req.body;
    const checked = await db.collection('shopping')
      .find({ ...shopScope(req.user), checked: true })
      .toArray();

    const toDelete = checked.filter(i => !isRepeating(i.repeat)).map(i => i._id);
    const toReset  = checked.filter(i =>  isRepeating(i.repeat)).map(i => i._id);

    if (toDelete.length)
      await db.collection('shopping').deleteMany({ _id: { $in: toDelete } });
    if (toReset.length && resetRepeating)
      await db.collection('shopping').updateMany(
        { _id: { $in: toReset } },
        { $set: { checked: false } }
      );

    res.json({ deleted: toDelete.length, reset: resetRepeating ? toReset.length : 0 });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── SHOP LISTS (Gastlisten) ───────────────────────
app.get('/api/shoplists', auth, async (req, res) => {
  try {
    const now = new Date();
    const lists = await db.collection('shoplists')
      .find({ ...shopScope(req.user) })
      .sort({ createdAt: -1 }).toArray();
    res.json(lists.map(l => ({ ...l, _id: l._id.toString(), expired: l.expiresAt < now })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/shoplists', auth, async (req, res) => {
  try {
    const { name, hours } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: 'Name fehlt' });
    const h = [24,48,72].includes(Number(hours)) ? Number(hours) : 24;
    const token = genToken();
    const doc = {
      ...shopScope(req.user),
      name: name.trim(), token,
      createdBy: req.user._id.toString(),
      hours: h, expiresAt: new Date(Date.now() + h * 3600000),
      createdAt: new Date()
    };
    const r = await db.collection('shoplists').insertOne(doc);
    res.json({ ...doc, _id: r.insertedId.toString() });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/shoplists/:id', auth, async (req, res) => {
  try {
    const list = await db.collection('shoplists').findOne({ _id: new ObjectId(req.params.id), ...shopScope(req.user) });
    if (!list) return res.status(404).json({ error: 'Nicht gefunden' });
    // Alle listentries dieser Liste löschen
    await db.collection('listentries').deleteMany({ listId: list._id.toString() });
    await db.collection('shoplists').deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/shoplists/guest/:token', async (req, res) => {
  try {
    const list = await db.collection('shoplists').findOne({ token: req.params.token });
    if (!list || list.expiresAt < new Date()) return res.status(404).json({ error: 'Abgelaufen' });
    res.json({ ...list, _id: list._id.toString() });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── LIST ENTRIES ──────────────────────────────────
// listId: 'wocheneinkauf' (default) | shoplist._id
function leScope(user) {
  return user.groupId ? { groupId: user.groupId } : { groupId: null, userId: user._id.toString() };
}

app.get('/api/listentries', auth, async (req, res) => {
  try {
    const entries = await db.collection('listentries').find(leScope(req.user)).toArray();
    res.json(entries.map(e => ({ ...e, _id: e._id.toString() })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/listentries', auth, async (req, res) => {
  try {
    const { articleId, listId } = req.body;
    if (!articleId) return res.status(400).json({ error: 'articleId fehlt' });
    const lid = listId || 'wocheneinkauf';
    // prevent duplicates
    const existing = await db.collection('listentries').findOne({ articleId, listId: lid, ...leScope(req.user) });
    if (existing) return res.json({ ...existing, _id: existing._id.toString() });
    const doc = { ...leScope(req.user), articleId, listId: lid, checked: false, createdAt: new Date() };
    const r = await db.collection('listentries').insertOne(doc);
    res.json({ ...doc, _id: r.insertedId.toString() });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/listentries/:id', async (req, res) => {
  // Supports both normal auth and guest auth
  const isGuest = req.headers['x-guest-token'];
  const authFn = isGuest ? guestAuth : auth;
  authFn(req, res, async () => {
    try {
      const scope = leScope(req.user);
      const update = {};
      if (req.body.checked !== undefined) update.checked = req.body.checked;
      const r = await db.collection('listentries').findOneAndUpdate(
        { _id: new ObjectId(req.params.id), ...scope },
        { $set: update }, { returnDocument: 'after' }
      );
      if (!r) return res.status(404).json({ error: 'Nicht gefunden' });
      res.json({ ...r, _id: r._id.toString() });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });
});

app.delete('/api/listentries/:id', auth, async (req, res) => {
  try {
    await db.collection('listentries').deleteOne({ _id: new ObjectId(req.params.id), ...leScope(req.user) });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Gast: listentries für eine Gastliste lesen
app.get('/api/listentries/guest/:token', async (req, res) => {
  try {
    const list = await db.collection('shoplists').findOne({ token: req.params.token });
    if (!list || list.expiresAt < new Date()) return res.status(404).json({ error: 'Abgelaufen' });
    const creator = await db.collection('users').findOne({ _id: new ObjectId(list.createdBy) });
    if (!creator) return res.status(404).json({ error: 'Nicht gefunden' });
    const scope = leScope(creator);
    const entries = await db.collection('listentries').find({ ...scope, listId: list._id.toString() }).toArray();
    const articleIds = [...new Set(entries.map(e => e.articleId))];
    const articles = await db.collection('shopping').find({ _id: { $in: articleIds.map(id => { try { return new ObjectId(id); } catch { return null; } }).filter(Boolean) } }).toArray();
    const artMap = new Map(articles.map(a => [a._id.toString(), a]));
    res.json({
      list: { ...list, _id: list._id.toString() },
      entries: entries.map(e => ({ ...e, _id: e._id.toString(), article: artMap.get(e.articleId) || null }))
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Artikel für Gastliste anlegen
app.post('/api/shopping/guest/:token', async (req, res) => {
  try {
    const list = await db.collection('shoplists').findOne({ token: req.params.token });
    if (!list || list.expiresAt < new Date()) return res.status(401).json({ error: 'Abgelaufen' });
    const creator = await db.collection('users').findOne({ _id: new ObjectId(list.createdBy) });
    if (!creator) return res.status(404).json({ error: 'Nicht gefunden' });
    const sc = shopScope(creator);
    const { title, category, qty, comment } = req.body;
    if (!title?.trim()) return res.status(400).json({ error: 'Titel fehlt' });
    const doc = { ...sc, title: title.trim(), category: category || 'Sonstiges', qty: qty || '', price: '', comment: comment || '', photos: [], photo: null, repeat: null, createdAt: new Date() };
    const r = await db.collection('shopping').insertOne(doc);
    const articleId = r.insertedId.toString();
    // Direkt als listentry für diese Gastliste anlegen
    const leDoc = { ...leScope(creator), articleId, listId: list._id.toString(), checked: false, createdAt: new Date() };
    const le = await db.collection('listentries').insertOne(leDoc);
    res.json({ article: { ...doc, _id: articleId }, entry: { ...leDoc, _id: le.insertedId.toString() } });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Migration: bestehende shopping.checked → listentries für wocheneinkauf
app.post('/api/migrate/listentries', auth, async (req, res) => {
  try {
    const sc = shopScope(req.user);
    const leSc = leScope(req.user);
    const items = await db.collection('shopping').find(sc).toArray();
    let created = 0;
    for (const item of items) {
      const aid = item._id.toString();
      const exists = await db.collection('listentries').findOne({ articleId: aid, listId: 'wocheneinkauf', ...leSc });
      if (!exists && item.checked) {
        await db.collection('listentries').insertOne({ ...leSc, articleId: aid, listId: 'wocheneinkauf', checked: true, createdAt: new Date() });
        created++;
      }
    }
    res.json({ ok: true, created });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── GUEST LINKS ───────────────────────────────────
app.get('/api/guestlinks/:token', async (req, res) => {
  try {
    const link = await db.collection('guestlinks').findOne({ token: req.params.token });
    if (!link || link.expiresAt < new Date()) return res.status(404).json({ error: 'Abgelaufen' });
    res.json({ ok: true, groupId: link.groupId, userId: link.userId });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/guestlinks', auth, async (req, res) => {
  try {
    const now = new Date();
    const links = await db.collection('guestlinks')
      .find({ createdBy: req.user._id.toString(), expiresAt: { $gt: now } })
      .sort({ createdAt: -1 }).toArray();
    res.json(links.map(l => ({ ...l, _id: l._id.toString() })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/guestlinks', auth, async (req, res) => {
  try {
    const hours = [24, 48, 72].includes(Number(req.body.hours)) ? Number(req.body.hours) : 24;
    const token = genToken();
    const expiresAt = new Date(Date.now() + hours * 3600000);
    const doc = {
      token, createdBy: req.user._id.toString(),
      groupId: req.user.groupId || null, userId: req.user._id.toString(),
      hours, expiresAt, createdAt: new Date()
    };
    await db.collection('guestlinks').insertOne(doc);
    res.json({ token, expiresAt });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/guestlinks/:token', auth, async (req, res) => {
  try {
    await db.collection('guestlinks').deleteOne({ token: req.params.token, createdBy: req.user._id.toString() });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Gast-Auth Middleware
async function guestAuth(req, res, next) {
  const token = req.headers['x-guest-token'];
  if (!token) return res.status(401).json({ error: 'Kein Gast-Token' });
  const link = await db.collection('guestlinks').findOne({ token });
  if (!link || link.expiresAt < new Date()) return res.status(401).json({ error: 'Link abgelaufen' });
  // Scope vom Link-Ersteller übernehmen
  const creator = await db.collection('users').findOne({ _id: new ObjectId(link.userId) });
  if (!creator) return res.status(401).json({ error: 'Ersteller nicht gefunden' });
  req.user = creator;
  req.guestName = req.headers['x-guest-name'] || 'Gast';
  req.isGuest = true;
  next();
}

// Gast-Shopping: nur lesen + checked togglen
app.get('/api/shopping', async (req, res, next) => {
  if (req.headers['x-guest-token']) return guestAuth(req, res, () => {
    db.collection('shopping').find(shopScope(req.user)).sort({ createdAt: 1 }).toArray()
      .then(items => res.json(items.map(i => ({ ...i, _id: i._id.toString() }))))
      .catch(e => res.status(500).json({ error: e.message }));
  });
  next();
});

app.patch('/api/shopping/:id', async (req, res, next) => {
  if (req.headers['x-guest-token']) return guestAuth(req, res, async () => {
    try {
      const filter = { _id: new ObjectId(req.params.id), ...shopScope(req.user) };
      // Gäste dürfen nur checked ändern
      const update = {};
      if (req.body.checked !== undefined) update.checked = req.body.checked;
      const r = await db.collection('shopping').findOneAndUpdate(filter, { $set: update }, { returnDocument: 'after' });
      if (!r) return res.status(404).json({ error: 'Nicht gefunden' });
      res.json({ ...r, _id: r._id.toString() });
    } catch(e) { res.status(500).json({ error: e.message }); }
  });
  next();
});

// ── CHECK LOG ─────────────────────────────────────
app.post('/api/checklog', auth, async (req, res) => {
  try {
    const { itemId, itemTitle, action, actor } = req.body;
    const sc = shopScope(req.user);
    await db.collection('checklogs').insertOne({
      ...sc, itemId, itemTitle, action, actor, createdAt: new Date()
    });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/checklog', async (req, res) => {
  const isGuest = req.headers['x-guest-token'];
  const authFn = isGuest ? guestAuth : auth;
  authFn(req, res, async () => {
    try {
      const sc = shopScope(req.user);
      const logs = await db.collection('checklogs')
        .find(sc).sort({ createdAt: 1 }).limit(200).toArray();
      res.json(logs.map(l => ({ ...l, _id: l._id.toString() })));
    } catch(e) { res.status(500).json({ error: e.message }); }
  });
});

// ── RECIPES ───────────────────────────────────────
app.get('/api/recipes', auth, async (req, res) => {
  try {
    const items = await db.collection('recipes')
      .find(shopScope(req.user))
      .sort({ createdAt: -1 })
      .toArray();
    res.json(items.map(i => ({ ...i, _id: i._id.toString() })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/recipes', auth, async (req, res) => {
  try {
    const { name, category, link, ingredients, notes, photo } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: 'Name fehlt' });
    const doc = {
      ...shopScope(req.user),
      name: name.trim(),
      category: category || 'Sonstiges',
      link: link || '',
      ingredients: Array.isArray(ingredients) ? ingredients : [],
      notes: notes || '',
      photo: photo || null,
      createdAt: new Date(),
    };
    const r = await db.collection('recipes').insertOne(doc);
    res.status(201).json({ ...doc, _id: r.insertedId.toString() });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/recipes/:id', auth, async (req, res) => {
  try {
    const filter = { _id: new ObjectId(req.params.id), ...shopScope(req.user) };
    const allowed = ['name','category','link','ingredients','notes','photo'];
    const update = {};
    allowed.forEach(f => { if (req.body[f] !== undefined) update[f] = req.body[f]; });
    const r = await db.collection('recipes').findOneAndUpdate(
      filter, { $set: update }, { returnDocument: 'after' }
    );
    if (!r) return res.status(404).json({ error: 'Nicht gefunden' });
    res.json({ ...r, _id: r._id.toString() });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/recipes/:id', auth, async (req, res) => {
  try {
    await db.collection('recipes').deleteOne({
      _id: new ObjectId(req.params.id), ...shopScope(req.user)
    });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── ESSENSPLAN ────────────────────────────────────

app.get('/api/mealplan', auth, async (req, res) => {
  try {
    const doc = await db.collection('mealplans').findOne(shopScope(req.user));
    res.json(doc?.plan || {});
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/mealplan', auth, async (req, res) => {
  try {
    const sc = shopScope(req.user);
    const plan = {};
    ['mo','di','mi','do','fr','sa','so'].forEach(d => {
      plan[d] = (req.body[d] || '').trim();
    });
    await db.collection('mealplans').updateOne(
      sc,
      { $set: { plan, updatedAt: new Date() } },
      { upsert: true }
    );
    res.json(plan);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── POLL ──────────────────────────────────────────
app.get('/api/poll', auth, async (req, res) => {
  try {
    const tasks = await db.collection('tasks').find(scope(req.user)).toArray();
    const users = await db.collection('users')
      .find(req.user.groupId ? { groupId: req.user.groupId } : { _id: req.user._id })
      .project({ token: 0, notifications: 0 })
      .toArray();
    const stateKey = req.user.groupId || req.user._id.toString();
    const appstate = await db.collection('appstate').findOne({ _id: stateKey });

    const shopLast = await db.collection('shopping')
      .find(shopScope(req.user))
      .sort({ createdAt: -1 })
      .limit(1)
      .toArray();
    const shopStamp = shopLast[0]?.createdAt?.getTime() || 0;

    const hash = crypto.createHash('md5')
      .update(
        JSON.stringify(tasks) +
        JSON.stringify(users) +
        JSON.stringify(appstate || {}) +
        shopStamp
      )
      .digest('hex');

    const me = await db.collection('users').findOne({ _id: req.user._id });
    res.json({
      hash,
      hasNotifications: (me?.notifications || []).length > 0,
      taskCount: tasks.filter(t => !t.done).length
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── ICAL KALENDER ─────────────────────────────────
app.get('/api/calendar/feed.ics', async (req, res) => {
  try {
    const token = req.query.token;
    if (!token) return res.status(401).send('Kein Token');
    const user = await db.collection('users').findOne({ token });
    if (!user) return res.status(401).send('Ungültiger Token');

    const uid = user._id.toString();
    const sc = user.groupId
      ? { groupId: user.groupId }
      : { groupId: null, ownerId: uid };
    const allTasks = await db.collection('tasks').find(sc).toArray();
    const stateKey = user.groupId || uid;
    const stateDoc = await db.collection('appstate').findOne({ _id: stateKey });
    const poolAssigns = stateDoc?.poolAssigns || {};

    function getMondayOf(dateStr) {
      const d = new Date(dateStr + 'T00:00:00');
      const day = d.getDay();
      const diff = (day === 0 ? -6 : 1 - day);
      d.setDate(d.getDate() + diff);
      return d;
    }
    function toDateStr(d) { return d.toISOString().slice(0, 10).replace(/-/g, ''); }
    function icalEscape(s) {
      return (s || '').replace(/\\/g, '\\\\').replace(/;/g, '\\;').replace(/,/g, '\\,').replace(/\n/g, '\\n');
    }

    const myEntries = [];
    for (const t of allTasks) {
      if (t.done) continue;
      const tid = t._id.toString();
      const isPool = t.inPool === true;
      const isShared = !isPool && t.type === 'shared';
      const isMine = !isPool && !isShared;

      if (isMine) {
        if (t.assignee !== uid || !t.deadline) continue;
        myEntries.push({ uid: tid, title: t.title, label: '✓', deadline: t.deadline, prio: t.prio || '–', cat: t.cat || '–' });
      } else if (isShared) {
        const involved = (t.sharedWith || []).includes(uid) || t.creatorId === uid;
        if (!involved || !t.deadline) continue;
        myEntries.push({ uid: tid, title: t.title, label: '👥', deadline: t.deadline, prio: t.prio || '–', cat: t.cat || '–' });
      } else if (isPool) {
        const assign = poolAssigns[tid];
        if (!assign || !t.deadline) continue;
        if (t.subtasks?.length > 0 && assign.subtaskAssignments) {
          const mySubs = t.subtasks.filter(s => !s.done && assign.subtaskAssignments[s.id] === uid);
          for (const sub of mySubs)
            myEntries.push({ uid: `${tid}-${sub.id}`, title: `${t.title}: ${sub.title}`, label: '🔄', deadline: t.deadline, prio: t.prio || '–', cat: t.cat || '–' });
        } else {
          if (assign.assignedUser !== uid) continue;
          myEntries.push({ uid: tid, title: t.title, label: '🔄', deadline: t.deadline, prio: t.prio || '–', cat: t.cat || '–' });
        }
      }
    }

    const todayD = new Date(); todayD.setHours(0,0,0,0);
    const diffToMon = todayD.getDay() === 0 ? -6 : 1 - todayD.getDay();
    const thisMonday = new Date(todayD);
    thisMonday.setDate(todayD.getDate() + diffToMon);

    const myPoolTitles = [];
    for (const t of allTasks) {
      if (!t.inPool) continue;
      const tid = t._id.toString();
      const assign = poolAssigns[tid];
      if (!assign) continue;
      if (t.subtasks?.length > 0 && assign.subtaskAssignments) {
        t.subtasks.filter(s => !s.done && assign.subtaskAssignments[s.id] === uid)
          .forEach(s => myPoolTitles.push(`${t.title}: ${s.title}`));
      } else {
        if (assign.assignedUser === uid && !t.done) myPoolTitles.push(t.title);
      }
    }

    const lines = [
      'BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//TaskFlow//DE', 'CALSCALE:GREGORIAN',
      'X-WR-CALNAME:TaskFlow – ' + (user.name || 'Meine Aufgaben'),
      'X-WR-CALDESC:Persönliche Aufgaben aus TaskFlow',
      'REFRESH-INTERVAL;VALUE=DURATION:PT1H', 'X-PUBLISHED-TTL:PT1H',
    ];

    const byWeek = {};
    for (const e of myEntries) {
      const mon = getMondayOf(e.deadline);
      const key = toDateStr(mon);
      if (!byWeek[key]) byWeek[key] = { mon, entries: [] };
      byWeek[key].entries.push(e);
    }

    for (const [weekKey, { mon, entries }] of Object.entries(byWeek)) {
      const sun = new Date(mon); sun.setDate(sun.getDate() + 7);
      const poolLines   = entries.filter(e => e.label==='🔄').map(e=>`  🔄 ${e.title} (fällig ${e.deadline.slice(8)}.${e.deadline.slice(5,7)}.)`);
      const ownLines    = entries.filter(e => e.label==='✓' ).map(e=>`  ✓ ${e.title} (fällig ${e.deadline.slice(8)}.${e.deadline.slice(5,7)}.)`);
      const sharedLines = entries.filter(e => e.label==='👥').map(e=>`  👥 ${e.title} (fällig ${e.deadline.slice(8)}.${e.deadline.slice(5,7)}.)`);
      let desc = '';
      if (poolLines.length)   desc += 'POOL-AUFGABEN:\n'       + poolLines.join('\n')   + '\n\n';
      if (ownLines.length)    desc += 'EIGENE AUFGABEN:\n'     + ownLines.join('\n')    + '\n\n';
      if (sharedLines.length) desc += 'GEMEINSAME AUFGABEN:\n' + sharedLines.join('\n');
      lines.push('BEGIN:VEVENT', `UID:week-${weekKey}-${uid}@taskflow`,
        `SUMMARY:${icalEscape('📋 Meine Aufgaben (' + entries.length + ')')}`,
        `DTSTART;VALUE=DATE:${toDateStr(mon)}`, `DTEND;VALUE=DATE:${toDateStr(sun)}`,
        `DESCRIPTION:${icalEscape(desc.trim())}`, 'TRANSP:TRANSPARENT', 'STATUS:CONFIRMED', 'END:VEVENT');
    }

    if (myPoolTitles.length > 0) {
      const poolDesc = myPoolTitles.map(t => `• ${t}`).join('\n');
      for (let i = 0; i < 7; i++) {
        const day = new Date(thisMonday); day.setDate(thisMonday.getDate() + i);
        const nextDay = new Date(day); nextDay.setDate(day.getDate() + 1);
        lines.push('BEGIN:VEVENT', `UID:pool-week-${toDateStr(thisMonday)}-day${i}-${uid}@taskflow`,
          `SUMMARY:${icalEscape('TaskFlow - Poolaufgaben')}`,
          `DTSTART;VALUE=DATE:${toDateStr(day)}`, `DTEND;VALUE=DATE:${toDateStr(nextDay)}`,
          `DESCRIPTION:${icalEscape(poolDesc)}`, 'TRANSP:TRANSPARENT', 'STATUS:CONFIRMED', 'END:VEVENT');
      }
    }

    for (const e of myEntries) {
      const nextDay = new Date(e.deadline + 'T00:00:00'); nextDay.setDate(nextDay.getDate() + 1);
      lines.push('BEGIN:VEVENT', `UID:dl-${e.uid}@taskflow`,
        `SUMMARY:${icalEscape(e.label + ' ' + e.title)}`,
        `DTSTART;VALUE=DATE:${e.deadline.replace(/-/g,'')}`, `DTEND;VALUE=DATE:${toDateStr(nextDay)}`,
        `DESCRIPTION:${icalEscape('Kategorie: ' + e.cat + '\nPriorität: ' + e.prio)}`,
        'TRANSP:TRANSPARENT', 'STATUS:CONFIRMED', 'END:VEVENT');
    }

    lines.push('END:VCALENDAR');
    res.setHeader('Content-Type', 'text/calendar; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="taskflow.ics"');
    res.send(lines.join('\r\n'));
  } catch(e) { res.status(500).send('Fehler: ' + e.message); }
});

// ── GUEST ROUTE (SPA) ─────────────────────────────
app.get('/guest/:token', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── CATCH-ALL (SPA) ───────────────────────────────
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── START ─────────────────────────────────────────
const PORT = process.env.PORT || 3000;
connectDB()
  .then(() => app.listen(PORT, () => console.log(`🚀 http://localhost:${PORT}`)))
  .catch(err => { console.error('❌', err.message); process.exit(1); });
