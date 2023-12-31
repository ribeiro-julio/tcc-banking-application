import express from "express";
import { rateLimit } from "express-rate-limit";

import { loginController } from "./controllers/login.js";
import {
  getMeController,
  patchPasswordController,
  patchPinController,
} from "./controllers/me.js";
import {
  otpDisableController,
  otpGenerateController,
  otpValidateController,
  otpVerifyController,
} from "./controllers/otp.js";
import { transferMoney } from "./controllers/transfer.js";
import { parseLog, logger } from "./logger.js";
import { PORT } from "./env.js";

const app = express();

app.use(express.json());

const rateLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 10,
  message: "Request limit reached. Try again in 5 minutes",
});

app.post("/api/login", rateLimiter, loginController);

app.get("/api/me", rateLimiter, getMeController);
app.patch("/api/me/password", rateLimiter, patchPasswordController);
app.patch("/api/me/pin", patchPinController);

app.post("/api/otp/disable", rateLimiter, otpDisableController);
app.post("/api/otp/generate", rateLimiter, otpGenerateController);
app.post("/api/otp/validate", rateLimiter, otpValidateController);
app.post("/api/otp/verify", rateLimiter, otpVerifyController);

app.post("/api/transfer", rateLimiter, transferMoney);

app.all("*", (req, res) => {
  const log = parseLog(req, "404 page accessed");
  logger.warn(log.message, log.data);

  res.status(404).json({
    error: `Not found`,
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
