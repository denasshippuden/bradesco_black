require("dotenv").config();
const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const multer = require("multer");
const { Pool } = require("pg");

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", true);
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 }, // 8MB
});

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.warn("DATABASE_URL nao configurada. Configure no .env.");
}
const SCHEMA = process.env.PGSCHEMA || "blacklists";
const TABLE = `${SCHEMA}.blacklist`;
const LOG_TABLE = `${SCHEMA}.blacklist_log`;
const AUTH_USER = process.env.LOGIN_USER || process.env.ADMIN_USER;
const AUTH_PASS = process.env.LOGIN_PASS || process.env.ADMIN_PASS;
const AUTH_SECRET =
  process.env.AUTH_SECRET ||
  process.env.SESSION_SECRET ||
  // fallback para nao bloquear login se esquecer de configurar (use um valor forte em prod)
  (AUTH_USER && AUTH_PASS
    ? crypto
        .createHash("sha256")
        .update(`${AUTH_USER}:${AUTH_PASS}`)
        .digest("hex")
    : "");

const sslEnv = (process.env.PGSSL || "").toLowerCase();
const useSsl =
  sslEnv === "true" || sslEnv === "1" || sslEnv === "yes" || sslEnv === "on";

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: useSsl ? { rejectUnauthorized: false } : false,
});

const BLACKLIST_TABLE_DEFINITION = `
  CREATE TABLE IF NOT EXISTS ${TABLE} (
    cpf TEXT PRIMARY KEY,
    updated_at TIMESTAMPTZ DEFAULT NOW()
  )
`;

const LOG_TABLE_DEFINITION = `
  CREATE TABLE IF NOT EXISTS ${LOG_TABLE} (
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
    created_at TIMESTAMPTZ DEFAULT NOW()
  )
`;

const PORT = process.env.PORT || 3000;
const CPF_HEADER = new Set(["cpf"]);

const LOG_DIR = path.join(__dirname, "logs");
const LOG_FILE = path.join(LOG_DIR, "app.log");
const parsedTtl = Number(process.env.SESSION_TTL_MS);
const SESSION_TTL_MS = Number.isFinite(parsedTtl)
  ? parsedTtl
  : 30 * 60 * 1000;
const PARSER_VERSION = "manual-v3";

const ensureLogDir = () => {
  if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR);
};
ensureLogDir();

const ensurePool = () => {
  if (!DATABASE_URL) {
    const error = new Error("DATABASE_URL nao configurada.");
    error.status = 500;
    throw error;
  }
};

const prepareConnection = async (client) => {
  await client.query(`CREATE SCHEMA IF NOT EXISTS ${SCHEMA}`);
  await client.query(BLACKLIST_TABLE_DEFINITION);
  await client.query(LOG_TABLE_DEFINITION);
  await client
    .query(`SET search_path TO ${SCHEMA}, public`)
    .catch((err) => console.error("Falha ao definir search_path:", err));
};

let dbReadyPromise;
const ensureDatabaseReady = async () => {
  ensurePool();
  if (!dbReadyPromise) {
    dbReadyPromise = pool
      .connect()
      .then(async (client) => {
        try {
          await prepareConnection(client);
        } finally {
          client.release();
        }
      })
      .catch((err) => {
        dbReadyPromise = null;
        throw err;
      });
  }
  return dbReadyPromise;
};

ensureDatabaseReady().catch((err) =>
  console.error("Falha ao preparar banco na inicializacao:", err)
);

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
    await ensureDatabaseReady();
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
      `INSERT INTO ${LOG_TABLE}
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

const assertAuthConfigured = () => {
  if (!AUTH_USER || !AUTH_PASS) {
    return "Login nao configurado no servidor (.env).";
  }
  if (!AUTH_SECRET) {
    return "AUTH_SECRET nao configurado no servidor (.env).";
  }
  return "";
};

const createSession = () => {
  const expiresAt = Date.now() + SESSION_TTL_MS;
  const payload = { user: AUTH_USER, exp: expiresAt };
  const base = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto
    .createHmac("sha256", AUTH_SECRET)
    .update(base)
    .digest("base64url");
  return { token: `${base}.${sig}`, expiresAt };
};

const verifySession = (token = "") => {
  if (!AUTH_SECRET) return null;
  if (!token.includes(".")) return null;
  const [base, sig] = token.split(".");
  if (!base || !sig) return null;
  const expected = crypto
    .createHmac("sha256", AUTH_SECRET)
    .update(base)
    .digest("base64url");
  if (
    expected.length !== sig.length ||
    !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))
  ) {
    return null;
  }
  try {
    const payload = JSON.parse(Buffer.from(base, "base64url").toString());
    if (!payload.exp || payload.exp <= Date.now()) return null;
    return payload;
  } catch (_err) {
    return null;
  }
};

const requireAuth = async (req, res, next) => {
  if (!AUTH_SECRET) {
    await logEvent("auth", 500, { ip: req.ip }, "AUTH_SECRET nao configurado");
    return res
      .status(500)
      .json({ error: "AUTH_SECRET nao configurado no servidor." });
  }
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7).trim()
    : "";
  const payload = token ? verifySession(token) : null;

  if (!payload) {
    await logEvent("auth", 401, { ip: req.ip }, "Token ausente, invalido ou expirado");
    return res
      .status(401)
      .json({ error: "Sessao expirada ou nao autenticada." });
  }

  req.auth = payload;
  next();
};

const normalizeCpf = (value = "") => value.replace(/\D/g, "");
const isValidCpf = (cpf) => cpf.length === 11;

const parseCsvLines = (buffer) => {
  // Coluna A e sempre CPF; tolera ; ou , , cabecalho opcional e qualquer quantidade de colunas/linhas.
  const text = buffer.toString("utf8").replace(/^\uFEFF/, "");
  const rawLines = text
    .split(/\r?\n/)
    .map((l) => l.replace(/\r$/, ""))
    .filter((l) => l.trim() !== "");
  if (!rawLines.length) return { rows: [], hasHeader: false, headerLine: "" };

  const chooseDelimiter = () => {
    const sample = rawLines.find((l) => /[;,]/.test(l)) || rawLines[0];
    if (sample.includes(";")) return ";"; // prioriza ; se houver
    if (sample.includes(",")) return ",";
    return "";
  };

  const cleanRaw = (value = "") =>
    value.replace(/\0/g, "").replace(/^\"|\"$/g, "").trim();

  const parseWithDelimiter = (delimiter) => {
    const firstField = (line) => {
      if (!line) return "";
      if (delimiter) {
        const cut = line.indexOf(delimiter);
        return cut === -1 ? line : line.slice(0, cut);
      }
      const cut = line.search(/[;,]/);
      return cut === -1 ? line : line.slice(0, cut);
    };

    const headerLine = rawLines[0];
    const headerFirst = cleanRaw(firstField(headerLine)).toLowerCase();
    const hasHeader = CPF_HEADER.has(headerFirst);
    const dataLines = hasHeader ? rawLines.slice(1) : rawLines;

    const rows = dataLines.map((line) => {
      const rawCpf = cleanRaw(firstField(line));
      const cpf = normalizeCpf(rawCpf);
      return { line, cpf, valid: isValidCpf(cpf) };
    });

    return { rows, hasHeader, headerLine };
  };

  const primary = chooseDelimiter();
  let parsed = parseWithDelimiter(primary);

  // Se nao achou nenhum CPF valido e houver outro delimitador possivel, tenta o alternativo.
  const hasValid = parsed.rows.some((r) => r.valid);
  if (!hasValid) {
    const alt = primary === ";" ? "," : ";";
    if (rawLines.some((l) => l.includes(alt))) {
      parsed = parseWithDelimiter(alt);
    }
  }

  return parsed;
};

const extractCpfsFromCsv = (buffer) => {
  const parsed = parseCsvLines(buffer);
  return parsed.rows
    .map((r) => normalizeCpf(r.cpf || ""))
    .filter(Boolean);
};

app.use(
  express.json({
    limit: "1mb",
  })
);
app.use((err, req, res, next) => {
  if (err?.type === "entity.parse.failed" || err instanceof SyntaxError) {
    logEvent("request", 400, { ip: req.ip }, "JSON invalido");
    return res
      .status(400)
      .json({ error: "JSON invalido no corpo da requisicao." });
  }
  next(err);
});
app.use(
  "/assets",
  express.static(path.join(__dirname, "assets"), {
    dotfiles: "deny",
    etag: true,
    maxAge: "1d",
  })
);

const sendIndex = (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
};

app.get("/", sendIndex);
app.get("/index.html", sendIndex);

app.post("/api/login", async (req, res) => {
  const { user, pass } = req.body || {};
  const ip = req.ip;
  const configError = assertAuthConfigured();
  if (configError) {
    await logEvent("login", 500, { ip }, configError);
    return res.status(500).json({ error: configError });
  }
  if (!user || !pass) {
    await logEvent("login", 400, { ip }, "Credenciais incompletas");
    return res
      .status(400)
      .json({ error: "Usuario e senha sao obrigatorios." });
  }

  const success = user === AUTH_USER && pass === AUTH_PASS;
  if (!success) {
    await logEvent("login", 401, { ip }, "Credenciais invalidas");
    return res.status(401).json({ error: "Credenciais invalidas." });
  }

  const session = createSession();
  const expiresIso = new Date(session.expiresAt).toISOString();
  await logEvent("login", 200, { ip, expiresAt: expiresIso });
  return res.json({
    ok: true,
    token: session.token,
    expiresAt: expiresIso,
    expiresInMs: SESSION_TTL_MS,
  });
});

app.post("/api/blacklist/check", requireAuth, async (req, res) => {
  const ip = req.ip;
  try {
    const cpf = normalizeCpf(String(req.body?.cpf || ""));
    if (!cpf) {
      await logEvent("check", 400, { ip }, "CPF nao informado");
      return res.status(400).json({ error: "CPF nao informado." });
    }
    if (!isValidCpf(cpf)) {
      await logEvent("check", 400, { ip }, "CPF invalido");
      return res.status(400).json({ error: "CPF invalido." });
    }

    await ensureDatabaseReady();
    const result = await pool.query(
      `SELECT 1 FROM ${TABLE} WHERE cpf = $1 LIMIT 1`,
      [cpf]
    );
    const blacklisted = result.rowCount > 0;
    await logEvent(
      "check",
      200,
      { ip, total_input: 1, output_count: blacklisted ? 1 : 0 },
      blacklisted ? "CPF na blacklist" : "CPF liberado"
    );
    return res.json({
      cpf,
      blacklisted,
      message: blacklisted
        ? "Cliente na lista negra"
        : "Cliente disponivel",
    });
  } catch (err) {
    console.error(err);
    const status = err.status || 500;
    await logEvent(
      "check",
      status,
      { ip, err: err.message },
      "Falha ao consultar CPF"
    );
    res
      .status(status)
      .json({ error: err.message || "Erro ao consultar CPF." });
  }
});

app.post(
  "/api/blacklist/import",
  requireAuth,
  upload.single("file"),
  async (req, res) => {
  const ip = req.ip;
  try {
    await ensureDatabaseReady();
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
        .json({ error: "Nenhum CPF valido encontrado no arquivo." });
    }

    const client = await pool.connect();
    let inserted = 0;
    let duplicates = 0;
    try {
      await client.query("BEGIN");
      const existing = await client.query(
        `SELECT cpf FROM ${TABLE} WHERE cpf = ANY($1)`,
        [validCpfs]
      );
      const existingSet = new Set(existing.rows.map((r) => r.cpf));
      duplicates = existingSet.size;

      const newCpfs = validCpfs.filter((cpf) => !existingSet.has(cpf));
      if (newCpfs.length) {
        const insertResult = await client.query(
          `INSERT INTO ${TABLE} (cpf, updated_at) SELECT unnest($1::text[]), NOW() ON CONFLICT (cpf) DO NOTHING`,
          [newCpfs]
        );
        inserted = insertResult.rowCount || 0;
      }

      // Atualiza updated_at de todos os validos (incluindo ja existentes)
      await client.query(
        `UPDATE ${TABLE} SET updated_at = NOW() WHERE cpf = ANY($1)`,
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
    await logEvent("import", status, { ip, err: err.message }, err.message);
    res.status(status).json({ error: err.message || "Erro interno." });
  }
});

app.get("/api/blacklist/export", requireAuth, async (req, res) => {
  const ip = req.ip;
  try {
    await ensureDatabaseReady();
    const result = await pool.query(
      `SELECT b.cpf FROM ${TABLE} b ORDER BY b.updated_at DESC`
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

app.post(
  "/api/blacklist/clean",
  requireAuth,
  upload.single("file"),
  async (req, res) => {
  const ip = req.ip;
  try {
    await ensureDatabaseReady();
    if (!req.file) {
      return res.status(400).json({ error: "Envie um arquivo CSV." });
    }
    const parsed = parseCsvLines(req.file.buffer);
    const seen = new Set();
    const validCpfs = [];
    parsed.rows.forEach((row) => {
      if (row.valid && !seen.has(row.cpf)) {
        seen.add(row.cpf);
        validCpfs.push(row.cpf);
      }
    });
    if (!validCpfs.length) {
      return res
        .status(400)
        .json({ error: "Nenhum CPF valido encontrado no arquivo." });
    }

    const blocked = await pool.query(
      `SELECT cpf FROM ${TABLE} WHERE cpf = ANY($1)`,
      [validCpfs]
    );
    const blockedSet = new Set(blocked.rows.map((r) => r.cpf));
    const cleanedRows = parsed.rows.filter(
      (row) => !row.valid || !blockedSet.has(row.cpf)
    );

    const lines = [];
    if (parsed.hasHeader) lines.push(parsed.headerLine);
    cleanedRows.forEach((row) => lines.push(row.line));
    await logEvent("clean", 200, {
      processed: validCpfs.length,
      total_input: parsed.rows.length,
      output_count: cleanedRows.length,
      ip,
    });
    res.setHeader("Content-Type", "text/csv");
    res.setHeader(
      "Content-Disposition",
      'attachment; filename="mailing_limpo.csv"'
    );
    res.setHeader("X-Records-Filtered", cleanedRows.length.toString());
    res.setHeader("X-Records-Input", parsed.rows.length.toString());
    res.setHeader("X-Parser-Version", PARSER_VERSION);
    res.send(lines.join("\n"));
  } catch (err) {
    console.error(err);
    await logEvent(
      "clean",
      err.status || 500,
      { ip, err: err.message },
      "Falha ao limpar mailing"
    );
    res.status(500).json({ error: "Falha ao limpar mailing." });
  }
});

// Quando rodando localmente, suba o servidor HTTP. Em ambiente serverless (Vercel),
// apenas exportamos o app e deixamos a plataforma cuidar do handler.
if (!process.env.VERCEL) {
  app.listen(PORT, "0.0.0.0", () => 
    console.log(`Rodando na porta ${PORT}`));
  };


module.exports = app;
