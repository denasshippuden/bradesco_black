require("dotenv").config();
const express = require("express");
const path = require("path");
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
      return res.json({
        inserted,
        duplicates,
        invalid,
        processed: validCpfs.length + invalid,
      });
    } catch (err) {
      await client.query("ROLLBACK");
      console.error("Erro no import:", err);
      return res.status(500).json({ error: "Falha ao importar CPFs." });
    } finally {
      client.release();
    }
  } catch (err) {
    const status = err.status || 500;
    console.error(err);
    res.status(status).json({ error: err.message || "Erro interno." });
  }
});

app.get("/api/blacklist/export", async (req, res) => {
  try {
    ensurePool();
    const result = await pool.query(
      "SELECT cpf FROM blacklist ORDER BY updated_at DESC"
    );
    const lines = ["cpf", ...result.rows.map((r) => r.cpf)];
    res.setHeader("Content-Type", "text/csv");
    res.setHeader(
      "Content-Disposition",
      'attachment; filename="blacklist.csv"'
    );
    res.send(lines.join("\n"));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Falha ao exportar BlackList." });
  }
});

app.post("/api/blacklist/clean", upload.single("file"), async (req, res) => {
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
    res.status(500).json({ error: "Falha ao limpar mailing." });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
