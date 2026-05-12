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

// ── Auth ───────────────────────────────────────────────────────────────────────
const APP_PASSWORD = process.env.APP_PASSWORD;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

function makeToken(prefix, password) {
  return crypto.createHash('sha256').update(prefix + ':' + password).digest('hex');
}

const VALID_TOKEN = APP_PASSWORD ? makeToken('gycfo', APP_PASSWORD) : null;
const VALID_ADMIN_TOKEN = ADMIN_PASSWORD ? makeToken('gycfo-admin', ADMIN_PASSWORD) : null;

function requireAuth(req, res, next) {
  if (!VALID_TOKEN) return next();
  if (req.headers['x-app-token'] === VALID_TOKEN) return next();
  res.status(401).json({ error: 'Nicht autorisiert' });
}

function requireAdminAuth(req, res, next) {
  if (!VALID_ADMIN_TOKEN) return next();
  if (req.headers['x-admin-token'] === VALID_ADMIN_TOKEN) return next();
  res.status(401).json({ error: 'Nicht autorisiert' });
}

app.post('/api/auth', (req, res) => {
  if (!VALID_TOKEN) return res.json({ ok: true, token: null });
  const { password } = req.body;
  if (!password || makeToken('gycfo', password) !== VALID_TOKEN) {
    return res.status(401).json({ error: 'Falsches Passwort' });
  }
  res.json({ ok: true, token: VALID_TOKEN });
});

app.post('/api/admin/auth', (req, res) => {
  if (!VALID_ADMIN_TOKEN) return res.json({ ok: true, token: null });
  const { password } = req.body;
  if (!password || makeToken('gycfo-admin', password) !== VALID_ADMIN_TOKEN) {
    return res.status(401).json({ error: 'Falsches Passwort' });
  }
  res.json({ ok: true, token: VALID_ADMIN_TOKEN });
});

// Static files
app.use(express.static(path.join(__dirname, 'public')));

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ── Analysis modules ───────────────────────────────────────────────────────────
const MODULE_SCHEMAS = {
  workshop_summary: {
    instruction: 'Erstelle eine strukturierte Workshop-Zusammenfassung mit Kontext & Ziel, Kernentscheidungen, Aktionspunkten (mit Verantwortlichem und Frist), offenen Fragen, OKR-relevanten Erkenntnissen und Teamstimmung.',
    schema: `"workshop_summary": {
    "kontext_ziel": "2-4 Sätze zu Kontext und Ziel",
    "kernentscheidungen": ["Entscheidung 1"],
    "aktionspunkte": [{"aufgabe": "Aufgabe", "verantwortlich": "Name oder null", "frist": "Datum oder null"}],
    "offene_fragen": ["Frage 1"],
    "okr_strategie_insights": ["Insight 1"],
    "stimmung_team": "2-3 Sätze zur Teamstimmung"
  }`,
  },
  okr_derivation: {
    instruction: 'Leite 2–4 konkrete OKRs aus dem Workshop-Inhalt ab. Objectives qualitativ-inspirierend, Key Results spezifisch und messbar.',
    schema: `"okr_derivation": {
    "objectives": [
      {"objective": "Qualitatives Ziel", "key_results": ["KR 1", "KR 2", "KR 3"], "begruendung": "Warum dieses OKR"}
    ]
  }`,
  },
  critical_analysis: {
    instruction: 'Analysiere kritisch: Was wird übersehen? Welche Risiken bestehen? Welche Widersprüche gibt es? Gib klare Handlungsempfehlungen.',
    schema: `"critical_analysis": {
    "blinde_flecken": ["Übersehener Aspekt 1"],
    "risiken": ["Risiko 1"],
    "widersprueche": ["Widerspruch 1"],
    "empfehlungen": ["Empfehlung 1"]
  }`,
  },
  strategic_gaps: {
    instruction: 'Identifiziere strategische Lücken: Wo ist die Strategie unvollständig, unklar oder widersprüchlich? Bewerte Schweregrad (hoch/mittel/niedrig).',
    schema: `"strategic_gaps": {
    "luecken": [{"bereich": "Bereich", "beschreibung": "Beschreibung der Lücke", "schwere": "hoch|mittel|niedrig"}],
    "fehlende_elemente": ["Fehlendes Element 1"]
  }`,
  },
  team_alignment: {
    instruction: 'Beurteile das Team-Alignment: Wo besteht Einigkeit, wo Spannungsfelder? Gesamtbewertung und konkrete Empfehlung.',
    schema: `"team_alignment": {
    "alignment_bewertung": "2-3 Sätze zur Gesamteinschätzung",
    "einigkeit_themen": ["Thema mit Einigkeit 1"],
    "spannungsfelder": ["Spannungsfeld 1"],
    "empfehlung": "Konkrete Empfehlung"
  }`,
  },
};

function buildSystemPrompt(selectedModules) {
  const valid = selectedModules.filter(m => MODULE_SCHEMAS[m]);
  const instructions = valid.map((m, i) => `${i + 1}. ${MODULE_SCHEMAS[m].instruction}`).join('\n');
  const schemas = valid.map(m => MODULE_SCHEMAS[m].schema).join(',\n  ');

  return `Du bist ein erfahrener Business-Analyst und Strategie-Berater bei GetYourCFO. Analysiere den Workshop-Inhalt und erstelle folgende Analysen:

${instructions}

Gib ausschließlich ein JSON-Objekt zurück mit genau diesen Keys: ${valid.join(', ')}

{
  ${schemas}
}

Regeln:
- Antworte NUR mit dem JSON-Objekt, ohne Markdown-Codeblöcke oder zusätzlichen Text
- Alle Werte auf Deutsch
- Extrahiere nur tatsächlich genannte Informationen, erfinde nichts
- Nullable Felder (verantwortlich, frist) auf null setzen wenn unbekannt`;
}

// ── Summaries storage ──────────────────────────────────────────────────────────
const SUMMARIES_DIR = process.env.STORAGE_PATH
  ? path.join(process.env.STORAGE_PATH, 'summaries')
  : path.join(__dirname, 'summaries');

if (!fs.existsSync(SUMMARIES_DIR)) {
  fs.mkdirSync(SUMMARIES_DIR, { recursive: true });
  console.log(`Summaries directory created: ${SUMMARIES_DIR}`);
}

function slugify(text) {
  return String(text)
    .toLowerCase()
    .replace(/[äöüß]/g, c => ({ ä: 'ae', ö: 'oe', ü: 'ue', ß: 'ss' }[c]))
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 40);
}

function saveSummary(results, selectedModules) {
  const now = new Date();
  const ts = now.toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const titleSource = results.workshop_summary?.kontext_ziel
    || results.okr_derivation?.objectives?.[0]?.objective
    || results.team_alignment?.alignment_bewertung
    || '';
  const titleWords = titleSource.split(/\s+/).slice(0, 6).join(' ');
  const slug = slugify(titleWords) || 'workshop';
  const id = `${ts}_${slug}`;

  const record = {
    id,
    timestamp: now.toISOString(),
    title: titleWords || 'Workshop',
    modules: selectedModules,
    results,
  };

  fs.writeFileSync(path.join(SUMMARIES_DIR, `${id}.json`), JSON.stringify(record, null, 2), 'utf-8');
  console.log(`Summary saved: ${id}.json`);
  return record;
}

app.get('/api/admin/summaries', requireAdminAuth, (req, res) => {
  try {
    const files = fs.readdirSync(SUMMARIES_DIR)
      .filter(f => f.endsWith('.json'))
      .sort()
      .reverse();

    const list = files.map(f => {
      const raw = fs.readFileSync(path.join(SUMMARIES_DIR, f), 'utf-8');
      const { id, timestamp, title, modules } = JSON.parse(raw);
      return { id, timestamp, title, modules, filename: f };
    });

    res.json(list);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/summaries/:filename', requireAdminAuth, (req, res) => {
  const filename = path.basename(req.params.filename);
  if (!filename.endsWith('.json')) return res.status(400).json({ error: 'Ungültige Datei' });
  const filePath = path.join(SUMMARIES_DIR, filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Nicht gefunden' });
  res.json(JSON.parse(fs.readFileSync(filePath, 'utf-8')));
});

// ── Knowledge base ─────────────────────────────────────────────────────────────
let knowledgeFiles = [];
let knowledgeText = '';

async function loadKnowledgeBase() {
  const knowledgeDir = path.join(__dirname, 'knowledge');
  if (!fs.existsSync(knowledgeDir)) {
    fs.mkdirSync(knowledgeDir, { recursive: true });
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
        const data = await pdfParse(fs.readFileSync(filePath));
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

// ── API routes ─────────────────────────────────────────────────────────────────
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
    return res.status(400).json({ error: 'Kein Inhalt übermittelt.' });
  }

  if (workshopContent.trim().length < 50) {
    return res.status(400).json({ error: 'Der Inhalt ist zu kurz für eine sinnvolle Analyse.' });
  }

  // Parse selected modules (JSON string from FormData or array from JSON body)
  let selectedModules = req.body.modules;
  if (typeof selectedModules === 'string') {
    try { selectedModules = JSON.parse(selectedModules); } catch { selectedModules = ['workshop_summary']; }
  }
  if (!Array.isArray(selectedModules) || selectedModules.length === 0) {
    selectedModules = ['workshop_summary'];
  }
  selectedModules = selectedModules.filter(m => MODULE_SCHEMAS[m]);

  const systemContent = [
    { type: 'text', text: buildSystemPrompt(selectedModules), cache_control: { type: 'ephemeral' } },
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
      messages: [{ role: 'user', content: `Analysiere den folgenden Workshop-Inhalt:\n\n${workshopContent}` }],
    });

    const rawText = response.content[0].text.trim();
    let results;
    try {
      results = JSON.parse(rawText);
    } catch {
      const match = rawText.match(/\{[\s\S]*\}/);
      if (match) results = JSON.parse(match[0]);
      else throw new Error('Claude hat kein gültiges JSON zurückgegeben.');
    }

    const saved = saveSummary(results, selectedModules);

    res.json({
      results,
      savedId: saved.id,
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
