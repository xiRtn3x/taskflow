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

if (!MONGO_URI) {
  console.error('\n❌ MONGO_URI fehlt! Erstelle eine .env Datei.\n');
  process.exit(1);
}

let db;
async function connectDB() {
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  db = client.db(DB_NAME);
  console.log('✅ MongoDB verbunden');
}

// ── Token generieren ──────────────────────────────────────
function genToken() {
  return crypto.randomBytes(32).toString('hex');
}

// ── Auth Middleware ───────────────────────────────────────
async function auth(req, res, next) {
  const token = req.headers['x-token'];
  if (!token) return res.status(401).json({ error: 'Kein Token' });
  const user = await db.collection('users').findOne({ token });
  if (!user) return res.status(401).json({ error: 'Ungültiger Token' });
  req.user = user;
  next();
}

// ═══════════════════════════════════════════════════════════
// USER ROUTES
// ═══════════════════════════════════════════════════════════

// Alle User laden (für Gruppen-Ansicht, nur Name+Farbe+Foto)
app.get('/api/users', auth, async (req, res) => {
  try {
    const u = req.user;
    let users = [];
    if (u.groupId) {
      const group = await db.collection('groups').findOne({ _id: new ObjectId(u.groupId) });
      if (group) {
        users = await db.collection('users')
          .find({ _id: { $in: group.memberIds.map(id => new ObjectId(id)) } })
          .project({ token: 0 })
          .toArray();
      }
    } else {
      users = [{ ...u, token: undefined }];
    }
    res.json(users);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// User registrieren / einloggen (nur Username)
app.post('/api/users/login', async (req, res) => {
  try {
    const { username } = req.body;
    if (!username?.trim()) return res.status(400).json({ error: 'Name fehlt' });

    let user = await db.collection('users').findOne({ name: username.trim() });
    if (!user) {
      // Neuer User
      const token = genToken();
      const result = await db.collection('users').insertOne({
        name: username.trim(),
        color: '#007AFF',
        photo: null,
        token,
        groupId: null,
        colorOverrides: {},   // { userId: color } — eigene Farbüberschreibungen
        notifications: [],
        createdAt: new Date()
      });
      user = await db.collection('users').findOne({ _id: result.insertedId });
    }
    res.json({ token: user.token, userId: user._id, isNew: !user.groupId && !user.solo });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Token validieren (Auto-Login)
app.get('/api/users/me', auth, async (req, res) => {
  const { token: _t, ...user } = req.user;
  res.json({ ...user, _id: user._id.toString() });
});

// Profil aktualisieren (nur eigenes)
app.patch('/api/users/me', auth, async (req, res) => {
  try {
    const { name, color, photo, colorOverrides } = req.body;
    const update = {};
    if (name) update.name = name.trim();
    if (color) update.color = color;
    if (photo !== undefined) update.photo = photo;
    if (colorOverrides) update.colorOverrides = colorOverrides;
    await db.collection('users').updateOne({ _id: req.user._id }, { $set: update });
    const updated = await db.collection('users').findOne({ _id: req.user._id });
    const { token: _t, ...safe } = updated;
    res.json({ ...safe, _id: safe._id.toString() });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// User löschen (nur sich selbst)
app.delete('/api/users/me', auth, async (req, res) => {
  try {
    const u = req.user;
    // Aus Gruppe entfernen
    if (u.groupId) {
      const group = await db.collection('groups').findOne({ _id: new ObjectId(u.groupId) });
      if (group) {
        if (group.creatorId.toString() === u._id.toString() && group.memberIds.length > 1) {
          return res.status(400).json({ error: 'Gruppe erst löschen oder übertragen bevor du dich löschst.' });
        }
        await db.collection('groups').updateOne(
          { _id: new ObjectId(u.groupId) },
          { $pull: { memberIds: u._id.toString() } }
        );
      }
    }
    // Aufgaben des Users löschen
    await db.collection('tasks').deleteMany({ assignee: u._id.toString(), groupId: u.groupId });
    await db.collection('users').deleteOne({ _id: u._id });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Notifications lesen & löschen
app.get('/api/users/notifications', auth, async (req, res) => {
  try {
    const notifs = req.user.notifications || [];
    res.json(notifs);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/users/notifications', auth, async (req, res) => {
  try {
    await db.collection('users').updateOne({ _id: req.user._id }, { $set: { notifications: [] } });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════
// GROUP ROUTES
// ═══════════════════════════════════════════════════════════

app.post('/api/groups', auth, async (req, res) => {
  try {
    const { name, photo } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: 'Name fehlt' });
    const result = await db.collection('groups').insertOne({
      name: name.trim(),
      photo: photo || null,
      creatorId: req.user._id.toString(),
      memberIds: [req.user._id.toString()],
      inviteCode: genToken().slice(0, 8).toUpperCase(),
      createdAt: new Date()
    });
    const group = await db.collection('groups').findOne({ _id: result.insertedId });
    // User updaten
    await db.collection('users').updateOne(
      { _id: req.user._id },
      { $set: { groupId: result.insertedId.toString(), solo: false } }
    );
    res.json({ ...group, _id: group._id.toString() });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Gruppe per Invite-Code beitreten
app.post('/api/groups/join', auth, async (req, res) => {
  try {
    const { inviteCode } = req.body;
    const group = await db.collection('groups').findOne({ inviteCode: inviteCode?.toUpperCase() });
    if (!group) return res.status(404).json({ error: 'Gruppe nicht gefunden' });
    const uid = req.user._id.toString();
    if (!group.memberIds.includes(uid)) {
      await db.collection('groups').updateOne(
        { _id: group._id },
        { $push: { memberIds: uid } }
      );
    }
    await db.collection('users').updateOne(
      { _id: req.user._id },
      { $set: { groupId: group._id.toString(), solo: false } }
    );
    res.json({ ...group, _id: group._id.toString() });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Gruppe laden
app.get('/api/groups/mine', auth, async (req, res) => {
  try {
    if (!req.user.groupId) return res.json(null);
    const group = await db.collection('groups').findOne({ _id: new ObjectId(req.user.groupId) });
    if (!group) return res.json(null);
    res.json({ ...group, _id: group._id.toString() });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Gruppe aktualisieren (nur Ersteller)
app.patch('/api/groups/mine', auth, async (req, res) => {
  try {
    const group = await db.collection('groups').findOne({ _id: new ObjectId(req.user.groupId) });
    if (!group) return res.status(404).json({ error: 'Keine Gruppe' });
    if (group.creatorId.toString() !== req.user._id.toString())
      return res.status(403).json({ error: 'Nur Ersteller darf Gruppe bearbeiten' });
    const { name, photo } = req.body;
    const update = {};
    if (name) update.name = name.trim();
    if (photo !== undefined) update.photo = photo;
    await db.collection('groups').updateOne({ _id: group._id }, { $set: update });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Gruppe löschen (nur Ersteller)
app.delete('/api/groups/mine', auth, async (req, res) => {
  try {
    const group = await db.collection('groups').findOne({ _id: new ObjectId(req.user.groupId) });
    if (!group) return res.status(404).json({ error: 'Keine Gruppe' });
    if (group.creatorId.toString() !== req.user._id.toString())
      return res.status(403).json({ error: 'Nur Ersteller darf Gruppe löschen' });
    // Alle Member aus Gruppe entfernen
    await db.collection('users').updateMany(
      { _id: { $in: group.memberIds.map(id => new ObjectId(id)) } },
      { $set: { groupId: null } }
    );
    await db.collection('tasks').deleteMany({ groupId: group._id.toString() });
    await db.collection('groups').deleteOne({ _id: group._id });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Gruppe verlassen
app.post('/api/groups/leave', auth, async (req, res) => {
  try {
    const u = req.user;
    if (!u.groupId) return res.status(400).json({ error: 'Nicht in einer Gruppe' });
    const group = await db.collection('groups').findOne({ _id: new ObjectId(u.groupId) });
    if (group && group.creatorId.toString() === u._id.toString() && group.memberIds.length > 1)
      return res.status(400).json({ error: 'Ersteller kann Gruppe nicht verlassen solange noch Mitglieder drin sind. Zuerst Gruppe löschen.' });
    await db.collection('groups').updateOne(
      { _id: new ObjectId(u.groupId) },
      { $pull: { memberIds: u._id.toString() } }
    );
    await db.collection('users').updateOne({ _id: u._id }, { $set: { groupId: null } });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════
// TASK ROUTES
// ═══════════════════════════════════════════════════════════

function taskScope(user) {
  // Aufgaben-Scope: groupId oder userId für Solo
  return user.groupId ? { groupId: user.groupId } : { groupId: null, ownerId: user._id.toString() };
}

app.get('/api/tasks', auth, async (req, res) => {
  try {
    const scope = taskScope(req.user);
    const tasks = await db.collection('tasks').find(scope).toArray();
    res.json(tasks.map(t => ({ ...t, _id: t._id.toString() })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/tasks', auth, async (req, res) => {
  try {
    const scope = taskScope(req.user);
    const task = {
      ...req.body,
      ...scope,
      creatorId: req.user._id.toString(),
      createdAt: new Date()
    };
    const result = await db.collection('tasks').insertOne(task);

    // Benachrichtigung an Empfänger wenn Aufgabe für anderen User erstellt
    const assignee = task.assignee;
    if (assignee && assignee !== 'all' && assignee !== req.user._id.toString()) {
      await db.collection('users').updateOne(
        { _id: new ObjectId(assignee) },
        { $push: { notifications: {
          id: genToken().slice(0,8),
          type: 'task_assigned',
          text: `📋 ${req.user.name} hat dir eine neue Aufgabe zugewiesen: „${task.title}"`,
          taskId: result.insertedId.toString(),
          createdAt: new Date()
        }}}
      );
    }

    res.json({ ...task, _id: result.insertedId.toString() });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/tasks/:id', auth, async (req, res) => {
  try {
    const task = await db.collection('tasks').findOne({ _id: new ObjectId(req.params.id) });
    if (!task) return res.status(404).json({ error: 'Nicht gefunden' });

    const update = { ...req.body };
    delete update._id;
    await db.collection('tasks').updateOne({ _id: new ObjectId(req.params.id) }, { $set: update });

    // Wenn Aufgabe als erledigt markiert → Ersteller benachrichtigen
    if (update.done === true && task.creatorId && task.creatorId !== req.user._id.toString()) {
      await db.collection('users').updateOne(
        { _id: new ObjectId(task.creatorId) },
        { $push: { notifications: {
          id: genToken().slice(0,8),
          type: 'task_done',
          text: `✅ ${req.user.name} hat „${task.title}" erledigt!`,
          taskId: req.params.id,
          createdAt: new Date()
        }}}
      );
    }

    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/tasks/:id', auth, async (req, res) => {
  try {
    await db.collection('tasks').deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── App-State (Pool, Einstellungen etc.) ──────────────────
// Pro Gruppe/User einen Konfigurationsdatensatz
app.get('/api/appstate', auth, async (req, res) => {
  try {
    const key = req.user.groupId || req.user._id.toString();
    const doc = await db.collection('appstate').findOne({ _id: key });
    if (!doc) return res.json({});
    const { _id, ...state } = doc;
    res.json(state);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/appstate', auth, async (req, res) => {
  try {
    const key = req.user.groupId || req.user._id.toString();
    const state = req.body;
    await db.collection('appstate').replaceOne({ _id: key }, { _id: key, ...state }, { upsert: true });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Polling: Änderungscheck ───────────────────────────────
// Gibt einen Hash zurück - wenn der sich ändert, muss das Frontend neu laden
app.get('/api/poll', auth, async (req, res) => {
  try {
    const scope = taskScope(req.user);
    const tasks = await db.collection('tasks').find(scope).toArray();
    const users = await db.collection('users')
      .find(req.user.groupId ? { groupId: req.user.groupId } : { _id: req.user._id })
      .project({ token: 0, notifications: 0 })
      .toArray();
    const notifs = req.user.notifications || [];
    const hash = crypto.createHash('md5')
      .update(JSON.stringify(tasks) + JSON.stringify(users))
      .digest('hex');
    res.json({ hash, hasNotifications: notifs.length > 0 });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Fallback ──────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start ─────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
connectDB().then(() => {
  app.listen(PORT, () => console.log(`🚀 Server läuft auf http://localhost:${PORT}`));
}).catch(err => {
  console.error('❌ MongoDB Verbindung fehlgeschlagen:', err.message);
  process.exit(1);
});
