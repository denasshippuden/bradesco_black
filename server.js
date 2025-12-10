require("dotenv").config();
const express = require("express");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const { parse } = require("csv-parse/sync");
const { Pool } = require("pg");

const app = express();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 }, // 8MB
});

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.warn("DATABASE_URL não configurada. Configure no .env.");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSL === "false" ? false : { rejectUnauthorized: false },
});

const PORT = process.env.PORT || 3000;
const CPF_HEADER = new Set(["cpf"]);

const LOG_DIR = path.join(__dirname, "logs");
const LOG_FILE = path.join(LOG_DIR, "app.log");

const ensureLogDir = () => {
  if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR);
};
ensureLogDir();

const logEvent = async (action, status, meta = {}, message = "") => {
  const line = {
    ts: new Date().toISOString(),
    action,
    status,
    message,
    ...meta,
  };
  try {
    fs.appendFileSync(LOG_FILE, `${JSON.stringify(line)}\n`);
  } catch (err) {
    console.error("Erro ao gravar log em arquivo:", err);
  }
  try {
    await pool.query(
      `CREATE TABLE IF NOT EXISTS blacklist_log (
         id SERIAL PRIMARY KEY,
         action TEXT,
         status INT,
         message TEXT,
         processed INT,
         inserted INT,
         duplicates INT,
         invalid INT,
         total_input INT,
         output_count INT,
         ip INET,
         created_at TIMESTAMP DEFAULT NOW()
       )`
    );
    const fields = {
      processed: meta.processed ?? null,
      inserted: meta.inserted ?? null,
      duplicates: meta.duplicates ?? null,
      invalid: meta.invalid ?? null,
      total_input: meta.total_input ?? null,
      output_count: meta.output_count ?? null,
      ip: meta.ip || null,
    };
    await pool.query(
      `INSERT INTO blacklist_log
       (action, status, message, processed, inserted, duplicates, invalid, total_input, output_count, ip)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [
        action,
        status,
        message || null,
        fields.processed,
        fields.inserted,
        fields.duplicates,
        fields.invalid,
        fields.total_input,
        fields.output_count,
        fields.ip,
      ]
    );
  } catch (err) {
    console.error("Erro ao gravar log no banco:", err);
  }
};

const normalizeCpf = (value = "") => value.replace(/\D/g, "");
const isValidCpf = (cpf) => cpf.length === 11;

const pickCpfFromRow = (row) => {
  const keys = Object.keys(row || {});
  if (!keys.length) return "";
  const matchKey = keys.find((k) => CPF_HEADER.has(k.toLowerCase())) || keys[0];
  return normalizeCpf(row[matchKey] || "");
};

const extractCpfsFromCsv = (buffer) => {
  // Primeiro, tenta com cabeçalho
  try {
    const rows = parse(buffer, {
      columns: (header) => header.map((h) => h.toLowerCase()),
      skip_empty_lines: true,
      trim: true,
    });
    if (Array.isArray(rows) && rows.length && typeof rows[0] === "object") {
      return rows.map(pickCpfFromRow).filter(Boolean);
    }
  } catch (err) {
    // fallback sem cabeçalho
  }
  const rows = parse(buffer, {
    columns: false,
    skip_empty_lines: true,
    trim: true,
  });
  return rows
    .map((r) => normalizeCpf(Array.isArray(r) ? r[0] : r))
    .filter(Boolean);
};

const ensurePool = () => {
  if (!DATABASE_URL) {
    const error = new Error("DATABASE_URL não configurada.");
    error.status = 500;
    throw error;
  }
};

app.use(express.json());
app.use(express.static(path.join(__dirname)));

app.post("/api/blacklist/import", upload.single("file"), async (req, res) => {
  const ip = req.ip;
  try {
    ensurePool();
    if (!req.file) {
      return res.status(400).json({ error: "Envie um arquivo CSV." });
    }
    const rawCpfs = extractCpfsFromCsv(req.file.buffer);
    const validSet = new Set();
    let invalid = 0;
    rawCpfs.forEach((cpf) => {
      if (isValidCpf(cpf)) validSet.add(cpf);
      else invalid += 1;
    });
    const validCpfs = Array.from(validSet);
    if (!validCpfs.length) {
      return res
        .status(400)
        .json({ error: "Nenhum CPF válido encontrado no arquivo." });
    }

    const client = await pool.connect();
    let inserted = 0;
    let duplicates = 0;
    try {
      await client.query("BEGIN");
      const existing = await client.query(
        "SELECT cpf FROM blacklist WHERE cpf = ANY($1)",
        [validCpfs]
      );
      const existingSet = new Set(existing.rows.map((r) => r.cpf));
      duplicates = existingSet.size;

      const newCpfs = validCpfs.filter((cpf) => !existingSet.has(cpf));
      if (newCpfs.length) {
        const insertResult = await client.query(
          "INSERT INTO blacklist (cpf, updated_at) SELECT unnest($1::text[]), NOW() ON CONFLICT (cpf) DO NOTHING",
          [newCpfs]
        );
        inserted = insertResult.rowCount || 0;
      }

      // Atualiza updated_at de todos os válidos (incluindo já existentes)
      await client.query(
        "UPDATE blacklist SET updated_at = NOW() WHERE cpf = ANY($1)",
        [validCpfs]
      );

      await client.query("COMMIT");
      const payload = {
        inserted,
        duplicates,
        invalid,
        processed: validCpfs.length + invalid,
      };
      await logEvent("import", 200, {
        ...payload,
        total_input: validCpfs.length + invalid,
        ip,
      });
      return res.json(payload);
    } catch (err) {
      await client.query("ROLLBACK");
      console.error("Erro no import:", err);
      await logEvent("import", 500, { ip }, "Erro no import");
      return res.status(500).json({ error: "Falha ao importar CPFs." });
    } finally {
      client.release();
    }
  } catch (err) {
    const status = err.status || 500;
    console.error(err);
    await logEvent("import", status, { ip }, err.message);
    res.status(status).json({ error: err.message || "Erro interno." });
  }
});

app.get("/api/blacklist/export", async (req, res) => {
  const ip = req.ip;
  try {
    ensurePool();
    const result = await pool.query(
      "SELECT cpf FROM blacklist ORDER BY updated_at DESC"
    );
    const lines = ["cpf", ...result.rows.map((r) => r.cpf)];
    await logEvent("export", 200, {
      processed: result.rowCount,
      output_count: result.rowCount,
      ip,
    });
    res.setHeader("Content-Type", "text/csv");
    res.setHeader(
      "Content-Disposition",
      'attachment; filename="blacklist.csv"'
    );
    res.send(lines.join("\n"));
  } catch (err) {
    console.error(err);
    await logEvent("export", 500, { ip }, "Falha ao exportar BlackList");
    res.status(500).json({ error: "Falha ao exportar BlackList." });
  }
});

app.post("/api/blacklist/clean", upload.single("file"), async (req, res) => {
  const ip = req.ip;
  try {
    ensurePool();
    if (!req.file) {
      return res.status(400).json({ error: "Envie um arquivo CSV." });
    }
    const rawCpfs = extractCpfsFromCsv(req.file.buffer);
    const seen = new Set();
    const validCpfs = [];
    rawCpfs.forEach((cpf) => {
      const norm = normalizeCpf(cpf);
      if (isValidCpf(norm) && !seen.has(norm)) {
        seen.add(norm);
        validCpfs.push(norm);
      }
    });
    if (!validCpfs.length) {
      return res
        .status(400)
        .json({ error: "Nenhum CPF válido encontrado no arquivo." });
    }

    const blocked = await pool.query(
      "SELECT cpf FROM blacklist WHERE cpf = ANY($1)",
      [validCpfs]
    );
    const blockedSet = new Set(blocked.rows.map((r) => r.cpf));
    const cleaned = validCpfs.filter((cpf) => !blockedSet.has(cpf));

    const lines = ["cpf", ...cleaned];
    await logEvent("clean", 200, {
      processed: validCpfs.length,
      total_input: validCpfs.length,
      output_count: cleaned.length,
      ip,
    });
    res.setHeader("Content-Type", "text/csv");
    res.setHeader(
      "Content-Disposition",
      'attachment; filename="mailing_limpo.csv"'
    );
    res.setHeader("X-Records-Filtered", cleaned.length.toString());
    res.setHeader("X-Records-Input", validCpfs.length.toString());
    res.send(lines.join("\n"));
  } catch (err) {
    console.error(err);
    await logEvent("clean", 500, { ip }, "Falha ao limpar mailing");
    res.status(500).json({ error: "Falha ao limpar mailing." });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
