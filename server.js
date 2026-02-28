require('dotenv').config();
const express = require('express');
const { MongoClient } = require('mongodb');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json({ limit: '10mb' })); // large limit for base64 photos
app.use(cors());

// â”€â”€ MongoDB â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const MONGO_URI = process.env.MONGO_URI;;
const DB_NAME   = 'taskflow';

let db;
async function connectDB() {
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  db = client.db(DB_NAME);
  console.log('âœ… MongoDB verbunden');
}

// â”€â”€ Statische Dateien (das Frontend) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.use(express.static(path.join(__dirname, 'public')));

// â”€â”€ API: State laden â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Der gesamte App-State wird als EIN Dokument gespeichert (einfach & schnell)
app.get('/api/state', async (req, res) => {
  try {
    const doc = await db.collection('appstate').findOne({ _id: 'main' });
    if (!doc) return res.json(null);
    const { _id, ...state } = doc;
    res.json(state);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Fehler beim Laden' });
  }
});

// â”€â”€ API: State speichern â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.post('/api/state', async (req, res) => {
  try {
    const state = req.body;
    await db.collection('appstate').replaceOne(
      { _id: 'main' },
      { _id: 'main', ...state },
      { upsert: true }
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Fehler beim Speichern' });
  }
});

// â”€â”€ Fallback: immer index.html ausliefern â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// â”€â”€ Start â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const PORT = process.env.PORT || 3000;
connectDB().then(() => {
  app.listen(PORT, () => console.log(`ðŸš€ Server lÃ¤uft auf Port ${PORT}`));
}).catch(err => {
  console.error('âŒ MongoDB Verbindung fehlgeschlagen:', err.message);
  process.exit(1);
});
