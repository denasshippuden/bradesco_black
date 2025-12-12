const app = require("../server");

// Handler para Vercel Serverless Functions: encaminha todas as rotas /api/* para o Express.
module.exports = (req, res) => app(req, res);
