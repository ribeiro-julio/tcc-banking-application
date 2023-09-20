import express from "express";

import { login } from "./controllers/login.js";

import { PORT } from "./env.js";

const app = express();

app.use(express.json());

app.post("/api/login", login);

app.all("*", (_, res) => {
  res.status(404).json({
    error: `Not found`,
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
