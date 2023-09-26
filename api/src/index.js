import express from "express";
import { rateLimit } from "express-rate-limit";

import { loginController } from "./controllers/login.js";
import { logger, parseLog } from "./logger.js";
import {
  otpDisableController,
  otpGenerateController,
  otpValidateController,
  otpVerifyController,
} from "./controllers/otp.js";
import { transferMoney } from "./controllers/transfer.js";
import { PORT } from "./env.js";

const app = express();

app.use(express.json());

const loginRateLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 10,
  message: "Request limit reached. Try again in 5 minutes",
});

app.post("/api/login", loginRateLimiter, loginController);
app.post("/api/otp/disable", otpDisableController);
app.post("/api/otp/generate", otpGenerateController);
app.post("/api/otp/validate", otpValidateController);
app.post("/api/otp/verify", loginRateLimiter, otpVerifyController);
api.post("api/transfer", transferMoney);

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
