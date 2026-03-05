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
  // Update lastVisit
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
      if (g) await db.collection('groups').updateOne({ _id: new ObjectId(u.groupId) }, { $pull: { memberIds: u._id.toString() } });
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
      if (g) list = await db.collection('users').find({ _id: { $in: g.memberIds.map(id => new ObjectId(id)) } }).project({ token: 0 }).toArray();
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
    await db.collection('users').updateOne({ _id: req.user._id }, { $set: { groupId: r.insertedId.toString(), solo: false } });
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
    await db.collection('users').updateOne({ _id: req.user._id }, { $set: { groupId: g._id.toString(), solo: false } });
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
    if (!g || g.creatorId !== req.user._id.toString()) return res.status(403).json({ error: 'Kein Zugriff' });
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
    if (!g || g.creatorId !== req.user._id.toString()) return res.status(403).json({ error: 'Kein Zugriff' });
    await db.collection('users').updateMany({ _id: { $in: g.memberIds.map(id => new ObjectId(id)) } }, { $set: { groupId: null } });
    await db.collection('tasks').deleteMany({ groupId: g._id.toString() });
    await db.collection('appstate').deleteOne({ _id: g._id.toString() });
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
    await db.collection('groups').updateOne({ _id: new ObjectId(u.groupId) }, { $pull: { memberIds: u._id.toString() } });
    await db.collection('users').updateOne({ _id: u._id }, { $set: { groupId: null } });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── TASKS ─────────────────────────────────────────
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
    const r = await db.collection('tasks').insertOne(task);
    // Notify assignee if different user
    const assignee = task.assignee;
    if (assignee && assignee !== 'all' && assignee !== req.user._id.toString()) {
      await db.collection('users').updateOne({ _id: new ObjectId(assignee) }, { $push: { notifications: {
        id: genToken().slice(0,8), type: 'task_assigned',
        text: `${req.user.name} hat dir eine neue Aufgabe zugewiesen: „${task.title}"`,
        taskId: r.insertedId.toString(), createdAt: new Date()
      }}});
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
      await db.collection('users').updateOne({ _id: new ObjectId(task.creatorId) }, { $push: { notifications: {
        id: genToken().slice(0,8), type: 'task_done',
        text: `${req.user.name} hat „${task.title}" erledigt!`,
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
    await db.collection('appstate').replaceOne({ _id: key }, { _id: key, ...req.body }, { upsert: true });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── POLL ──────────────────────────────────────────
app.get('/api/poll', auth, async (req, res) => {
  try {
    const tasks = await db.collection('tasks').find(scope(req.user)).toArray();
    const users = await db.collection('users')
      .find(req.user.groupId ? { groupId: req.user.groupId } : { _id: req.user._id })
      .project({ token: 0, notifications: 0 }).toArray();
    const hash = crypto.createHash('md5').update(JSON.stringify(tasks)+JSON.stringify(users)).digest('hex');
    const me = await db.collection('users').findOne({ _id: req.user._id });
    res.json({ hash, hasNotifications: (me?.notifications||[]).length > 0, taskCount: tasks.filter(t=>!t.done).length });
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

    // Load all tasks in scope
    const sc = user.groupId
      ? { groupId: user.groupId }
      : { groupId: null, ownerId: uid };
    const allTasks = await db.collection('tasks').find(sc).toArray();

    // Load appstate to get pool assignments
    const stateKey = user.groupId || uid;
    const stateDoc = await db.collection('appstate').findOne({ _id: stateKey });
    const poolAssigns = stateDoc?.poolAssigns || {};

    // Helper: get monday of a given date (YYYY-MM-DD)
    function getMondayOf(dateStr) {
      const d = new Date(dateStr + 'T00:00:00');
      const day = d.getDay(); // 0=Sun,1=Mon,...
      const diff = (day === 0 ? -6 : 1 - day);
      d.setDate(d.getDate() + diff);
      return d;
    }
    function toDateStr(d) {
      return d.toISOString().slice(0, 10).replace(/-/g, '');
    }
    function icalEscape(s) {
      return (s || '').replace(/\\/g, '\\\\').replace(/;/g, '\\;').replace(/,/g, '\\,').replace(/\n/g, '\\n');
    }
    // Fold long lines per RFC 5545 (max 75 octets)
    function fold(line) {
      const bytes = Buffer.from(line, 'utf8');
      if (bytes.length <= 75) return line;
      const parts = [];
      let start = 0;
      while (start < bytes.length) {
        const chunk = bytes.slice(start, start + (start === 0 ? 75 : 74));
        parts.push((start === 0 ? '' : ' ') + chunk.toString('utf8'));
        start += (start === 0 ? 75 : 74);
      }
      return parts.join('\r\n');
    }

    // ── Build personal task list ──────────────────
    // Each entry: { title, label, deadline, startDate, prio, cat, done }
    const myEntries = [];

    for (const t of allTasks) {
      if (t.done) continue;
      const tid = t._id.toString();
      const isPool = t.inPool === true;
      const isShared = !isPool && t.type === 'shared';
      const isMine = !isPool && !isShared;

      if (isMine) {
        // Own task: only if assigned to me
        if (t.assignee !== uid) continue;
        if (!t.deadline) continue;
        myEntries.push({
          uid: tid,
          title: t.title,
          label: '✓',
          deadline: t.deadline,
          startDate: t.createdAt ? new Date(t.createdAt).toISOString().slice(0,10) : t.deadline,
          prio: t.prio || '–',
          cat: t.cat || '–',
        });

      } else if (isShared) {
        // Shared task: only if I am in sharedWith or creator
        const involved = (t.sharedWith || []).includes(uid) || t.creatorId === uid;
        if (!involved) continue;
        if (!t.deadline) continue;
        myEntries.push({
          uid: tid,
          title: t.title,
          label: '👥',
          deadline: t.deadline,
          startDate: t.createdAt ? new Date(t.createdAt).toISOString().slice(0,10) : t.deadline,
          prio: t.prio || '–',
          cat: t.cat || '–',
        });

      } else if (isPool) {
        const assign = poolAssigns[tid];
        if (!assign) continue;

        if (t.subtasks && t.subtasks.length > 0 && assign.subtaskAssignments) {
          // Has subtasks: only include subtasks assigned to me
          const mySubs = t.subtasks.filter(s =>
            !s.done && assign.subtaskAssignments[s.id] === uid
          );
          if (!mySubs.length) continue;
          if (!t.deadline) continue;
          // One entry per subtask
          for (const sub of mySubs) {
            myEntries.push({
              uid: `${tid}-${sub.id}`,
              title: `${t.title}: ${sub.title}`,
              label: '🔄',
              deadline: t.deadline,
              startDate: t.createdAt ? new Date(t.createdAt).toISOString().slice(0,10) : t.deadline,
              prio: t.prio || '–',
              cat: t.cat || '–',
            });
          }
        } else {
          // No subtasks: only if main assignee is me
          if (assign.assignedUser !== uid) continue;
          if (!t.deadline) continue;
          myEntries.push({
            uid: tid,
            title: t.title,
            label: '🔄',
            deadline: t.deadline,
            startDate: t.createdAt ? new Date(t.createdAt).toISOString().slice(0,10) : t.deadline,
            prio: t.prio || '–',
            cat: t.cat || '–',
          });
        }
      }
    }

    // ── Build iCal lines ──────────────────────────
    const lines = [
      'BEGIN:VCALENDAR',
      'VERSION:2.0',
      'PRODID:-//TaskFlow//DE',
      'CALSCALE:GREGORIAN',
      'X-WR-CALNAME:TaskFlow – ' + (user.name || 'Meine Aufgaben'),
      'X-WR-CALDESC:Persönliche Aufgaben aus TaskFlow',
      'REFRESH-INTERVAL;VALUE=DURATION:PT1H',
      'X-PUBLISHED-TTL:PT1H',
    ];

    // Group entries by calendar week (Mon–Sun of deadline)
    const byWeek = {};
    for (const e of myEntries) {
      const mon = getMondayOf(e.deadline);
      const key = toDateStr(mon); // YYYYMMDD of monday
      if (!byWeek[key]) byWeek[key] = { mon, entries: [] };
      byWeek[key].entries.push(e);
    }

    // 1. Weekly digest events (one all-day event Mon→Sun per week)
    for (const [weekKey, { mon, entries }] of Object.entries(byWeek)) {
      const sun = new Date(mon);
      sun.setDate(sun.getDate() + 7); // DTEND is exclusive, so +7 = next Monday = full week

      // Build description
      const poolLines = entries.filter(e => e.label === '🔄').map(e =>
        `  🔄 ${e.title} (fällig ${e.deadline.slice(8)}.${e.deadline.slice(5,7)}.)`
      );
      const ownLines = entries.filter(e => e.label === '✓').map(e =>
        `  ✓ ${e.title} (fällig ${e.deadline.slice(8)}.${e.deadline.slice(5,7)}.)`
      );
      const sharedLines = entries.filter(e => e.label === '👥').map(e =>
        `  👥 ${e.title} (fällig ${e.deadline.slice(8)}.${e.deadline.slice(5,7)}.)`
      );

      let desc = '';
      if (poolLines.length) desc += 'POOL-AUFGABEN:\n' + poolLines.join('\n') + '\n\n';
      if (ownLines.length) desc += 'EIGENE AUFGABEN:\n' + ownLines.join('\n') + '\n\n';
      if (sharedLines.length) desc += 'GEMEINSAME AUFGABEN:\n' + sharedLines.join('\n');
      desc = desc.trim();

      const totalDone = entries.filter(e => e.done).length;
      const summary = `📋 Meine Aufgaben (${entries.length})`;

      lines.push(
        'BEGIN:VEVENT',
        `UID:week-${weekKey}-${uid}@taskflow`,
        `SUMMARY:${icalEscape(summary)}`,
        `DTSTART;VALUE=DATE:${toDateStr(mon)}`,
        `DTEND;VALUE=DATE:${toDateStr(sun)}`,
        `DESCRIPTION:${icalEscape(desc)}`,
        'TRANSP:TRANSPARENT',
        'STATUS:CONFIRMED',
        'END:VEVENT'
      );
    }

    // 2. Individual deadline markers (single-day, transparent)
    for (const e of myEntries) {
      const nextDay = new Date(e.deadline + 'T00:00:00');
      nextDay.setDate(nextDay.getDate() + 1);
      lines.push(
        'BEGIN:VEVENT',
        `UID:dl-${e.uid}@taskflow`,
        `SUMMARY:${icalEscape(e.label + ' ' + e.title)}`,
        `DTSTART;VALUE=DATE:${e.deadline.replace(/-/g, '')}`,
        `DTEND;VALUE=DATE:${toDateStr(nextDay)}`,
        `DESCRIPTION:${icalEscape('Kategorie: ' + e.cat + '\nPriorität: ' + e.prio)}`,
        'TRANSP:TRANSPARENT',
        'STATUS:CONFIRMED',
        'END:VEVENT'
      );
    }

    lines.push('END:VCALENDAR');

    res.setHeader('Content-Type', 'text/calendar; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="taskflow.ics"');
    res.send(lines.join('\r\n'));
  } catch(e) { res.status(500).send('Fehler: ' + e.message); }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3000;
connectDB().then(() => app.listen(PORT, () => console.log(`🚀 http://localhost:${PORT}`))).catch(err => { console.error('❌', err.message); process.exit(1); });
