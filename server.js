import Anthropic from '@anthropic-ai/sdk';
import express from 'express';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });
const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

app.use(express.json({ limit: '10mb' }));

// ── Auth ──────────────────────────────────────────────────────────────────────
const APP_PASSWORD = process.env.APP_PASSWORD;

function makeToken(password) {
  return crypto.createHash('sha256').update('gycfo:' + password).digest('hex');
}

const VALID_TOKEN = APP_PASSWORD ? makeToken(APP_PASSWORD) : null;

function requireAuth(req, res, next) {
  if (!VALID_TOKEN) return next();
  const token = req.headers['x-app-token'];
  if (token === VALID_TOKEN) return next();
  res.status(401).json({ error: 'Nicht autorisiert' });
}

app.post('/api/auth', (req, res) => {
  if (!VALID_TOKEN) return res.json({ ok: true, token: null });
  const { password } = req.body;
  if (!password || makeToken(password) !== VALID_TOKEN) {
    return res.status(401).json({ error: 'Falsches Passwort' });
  }
  res.json({ ok: true, token: VALID_TOKEN });
});

// Static files served before auth — login page needs to load
app.use(express.static(path.join(__dirname, 'public')));

// ── Knowledge base ─────────────────────────────────────────────────────────────
let knowledgeFiles = [];
let knowledgeText = '';

async function loadKnowledgeBase() {
  const knowledgeDir = path.join(__dirname, 'knowledge');
  if (!fs.existsSync(knowledgeDir)) {
    fs.mkdirSync(knowledgeDir, { recursive: true });
    console.log('Created knowledge/ directory');
    return;
  }

  const files = fs.readdirSync(knowledgeDir);
  const supported = files.filter(f => /\.(pdf|txt|md)$/i.test(f));

  const chunks = [];
  for (const file of supported) {
    const filePath = path.join(knowledgeDir, file);
    try {
      let text = '';
      if (file.toLowerCase().endsWith('.pdf')) {
        const pdfParse = (await import('pdf-parse')).default;
        const buffer = fs.readFileSync(filePath);
        const data = await pdfParse(buffer);
        text = data.text;
      } else {
        text = fs.readFileSync(filePath, 'utf-8');
      }
      chunks.push(`--- Datei: ${file} ---\n${text.trim()}`);
      knowledgeFiles.push(file);
      console.log(`Loaded knowledge file: ${file}`);
    } catch (err) {
      console.error(`Failed to load ${file}:`, err.message);
    }
  }

  knowledgeText = chunks.join('\n\n');
  console.log(`Knowledge base ready: ${knowledgeFiles.length} file(s)`);
}

const BASE_SYSTEM_PROMPT = `Du bist ein erfahrener Business-Analyst und Strategie-Berater bei GetYourCFO. Deine Aufgabe ist es, Workshop-Notizen und Transkripte präzise und strukturiert zusammenzufassen.

Analysiere den eingereichten Workshop-Inhalt und gib eine strukturierte Zusammenfassung als JSON zurück.

Das JSON muss exakt diesem Schema folgen:
{
  "kontext_ziel": "Kurze Beschreibung des Workshop-Kontexts und Ziels (2-4 Sätze)",
  "kernentscheidungen": ["Entscheidung 1", "Entscheidung 2", ...],
  "aktionspunkte": [
    {"aufgabe": "Aufgabenbeschreibung", "verantwortlich": "Name oder null", "frist": "Datum/Zeitraum oder null"},
    ...
  ],
  "offene_fragen": ["Frage 1", "Frage 2", ...],
  "okr_strategie_insights": ["Insight 1", "Insight 2", ...],
  "stimmung_team": "Qualitative Beschreibung der Teamstimmung und Alignment (2-3 Sätze)"
}

Regeln:
- Antworte NUR mit dem JSON-Objekt, ohne Markdown-Codeblöcke oder zusätzlichen Text
- Alle Werte auf Deutsch
- Sei präzise und handlungsorientiert
- Extrahiere nur tatsächlich genannte Informationen, erfinde nichts
- Bei fehlenden Informationen für "verantwortlich" oder "frist" setze null`;

// ── API routes (protected) ─────────────────────────────────────────────────────
app.get('/api/knowledge', requireAuth, (req, res) => {
  res.json({ files: knowledgeFiles, count: knowledgeFiles.length });
});

app.post('/api/summarize', requireAuth, upload.single('file'), async (req, res) => {
  let workshopContent = '';

  if (req.file) {
    if (req.file.mimetype === 'application/pdf' || req.file.originalname.toLowerCase().endsWith('.pdf')) {
      const pdfParse = (await import('pdf-parse')).default;
      const data = await pdfParse(req.file.buffer);
      workshopContent = data.text;
    } else {
      workshopContent = req.file.buffer.toString('utf-8');
    }
  } else if (req.body.text) {
    workshopContent = req.body.text;
  } else {
    return res.status(400).json({ error: 'Kein Inhalt übermittelt. Bitte Text eingeben oder Datei hochladen.' });
  }

  if (workshopContent.trim().length < 50) {
    return res.status(400).json({ error: 'Der Inhalt ist zu kurz für eine sinnvolle Analyse.' });
  }

  const systemContent = [
    { type: 'text', text: BASE_SYSTEM_PROMPT, cache_control: { type: 'ephemeral' } },
  ];

  if (knowledgeText) {
    systemContent.push({
      type: 'text',
      text: `Wissensbasis (Unternehmenskontext und Frameworks):\n\n${knowledgeText}`,
      cache_control: { type: 'ephemeral' },
    });
  }

  try {
    const response = await client.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 4096,
      system: systemContent,
      messages: [
        {
          role: 'user',
          content: `Analysiere den folgenden Workshop-Inhalt und erstelle eine strukturierte Zusammenfassung:\n\n${workshopContent}`,
        },
      ],
    });

    const rawText = response.content[0].text.trim();
    let summary;
    try {
      summary = JSON.parse(rawText);
    } catch {
      const match = rawText.match(/\{[\s\S]*\}/);
      if (match) {
        summary = JSON.parse(match[0]);
      } else {
        throw new Error('Claude hat kein gültiges JSON zurückgegeben.');
      }
    }

    res.json({
      summary,
      usage: {
        input_tokens: response.usage.input_tokens,
        output_tokens: response.usage.output_tokens,
        cache_read: response.usage.cache_read_input_tokens || 0,
        cache_created: response.usage.cache_creation_input_tokens || 0,
      },
    });
  } catch (err) {
    console.error('Summarize error:', err);
    res.status(500).json({ error: err.message || 'Interner Serverfehler' });
  }
});

const PORT = process.env.PORT || 8080;

loadKnowledgeBase().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Workshop Summarizer läuft auf http://0.0.0.0:${PORT}`);
    if (!VALID_TOKEN) console.log('Hinweis: APP_PASSWORD nicht gesetzt — Passwortschutz deaktiviert');
  });
});
