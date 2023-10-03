import { PrismaClient } from "@prisma/client";
import jwt from "jsonwebtoken";
import * as OTPAuth from "otpauth";
import CryptoJS from "crypto-js";
import pkg from "hi-base32";
import crypto from "crypto";

import {
  requestHasEmptyBody,
  requestHasTokenOnBody,
} from "../helpers/validators.js";
import { getAuthenticatedUser } from "../helpers/auth.js";
import { parseLog, logger, parseErrorLog } from "../logger.js";
import { TOTP_SECRET_ENCRYPTION_KEY, JWT_SECRET } from "../env.js";
import { validOtp } from "../helpers/validators.js";

export async function otpDisableController(req, res) {
  if (!requestHasEmptyBody(req)) {
    return res.status(400).json({ error: "Request body must be empty" });
  }

  const user = await getAuthenticatedUser(req, "authorized");

  if (user === null) return res.status(401).json({ error: "Unauthorized" });

  try {
    const prisma = new PrismaClient();

    if (!user.otp_enabled && user.otp_secret === null) {
      const log = parseLog(req, `User ${user.id} - OTP must be enabled`);
      logger.warn(log.message, log.data);

      return res.status(422).json({ error: "OTP must be enabled" });
    }

    await prisma.user.update({
      where: { id: user.id },
      data: {
        otp_enabled: false,
        otp_secret: null,
      },
    });

    const log = parseLog(req, `User ${user.id} - OTP disabled`);
    logger.info(log.message, log.data);

    return res.status(200).json({
      token: jwt.sign({ userId: user.id, authorized: true }, JWT_SECRET, {
        expiresIn: "15m",
      }),
    });
  } catch (error) {
    const log = parseErrorLog(req, error);
    logger.error(log.message, log.data);

    res.status(500).json({ error: "Internal server error" });
  }
}

export async function otpGenerateController(req, res) {
  if (!requestHasEmptyBody(req)) {
    return res.status(400).json({ error: "Request body must be empty" });
  }

  const user = await getAuthenticatedUser(req, "authorized");

  if (user === null) return res.status(401).json({ error: "Unauthorized" });

  try {
    const prisma = new PrismaClient();

    if (user.otp_enabled && user.otp_secret !== null) {
      const log = parseLog(req, `User ${user.id} - OTP must be disabled`);
      logger.warn(log.message, log.data);

      return res.status(422).json({ error: "OTP must be disabled" });
    }

    const otpSecret = otpSecretGenerate();

    const totp = new OTPAuth.TOTP({
      issuer: "tcc-banking-application.com",
      label: "TCC Banking Application",
      algorithm: "SHA1",
      digits: 6,
      secret: otpSecret,
    });

    await prisma.user.update({
      where: { id: user.id },
      data: {
        otp_secret: CryptoJS.AES.encrypt(
          otpSecret,
          TOTP_SECRET_ENCRYPTION_KEY
        ).toString(),
      },
    });

    const log = parseLog(req, `User ${user.id} - OTP generated`);
    logger.info(log.message, log.data);

    return res.status(200).json({ url: totp.toString(), secret: otpSecret });
  } catch (error) {
    const log = parseErrorLog(req, error);
    logger.error(log.message, log.data);

    res.status(500).json({ error: "Internal server error" });
  }
}

export async function otpValidateController(req, res) {
  if (!requestHasTokenOnBody(req)) {
    return res
      .status(400)
      .json({ error: "Request body must contain the token" });
  }

  const user = await getAuthenticatedUser(req, "unauthorized");

  if (user === null) return res.status(401).json({ error: "Unauthorized" });

  try {
    if (!user.otp_enabled || user.otp_secret === null) {
      const log = parseLog(req, `User ${user.id} - OTP must be active`);
      logger.warn(log.message, log.data);

      return res.status(422).json({ error: "OTP must be active" });
    }

    const { token } = req.body;

    if (!validOtp(token)) {
      const log = parseLog(req, `User ${user.id} - Invalid token`);
      logger.warn(log.message, log.data);

      return res.status(422).json({ error: "Invalid token" });
    }

    const totp = new OTPAuth.TOTP({
      issuer: "tcc-banking-application.com",
      label: "TCC Banking Application",
      algorithm: "SHA1",
      digits: 6,
      secret: CryptoJS.AES.decrypt(
        user.otp_secret,
        TOTP_SECRET_ENCRYPTION_KEY
      ).toString(CryptoJS.enc.Utf8),
    });

    if (totp.validate({ token: token, window: 1 }) === null) {
      const log = parseLog(req, `User ${user.id} - Wrong token`);
      logger.warn(log.message, log.data);

      return res.status(401).json({ error: "Wrong token" });
    }

    const log = parseLog(req, `User ${user.id} - OTP validated`);
    logger.info(log.message, log.data);

    return res.status(200).json({
      token: jwt.sign({ userId: user.id, authorized: true }, JWT_SECRET, {
        expiresIn: "15m",
      }),
    });
  } catch (error) {
    const log = parseErrorLog(req, error);
    logger.error(log.message, log.data);

    res.status(500).json({ error: "Internal server error" });
  }
}

export async function otpVerifyController(req, res) {
  if (!requestHasTokenOnBody(req)) {
    return res
      .status(400)
      .json({ error: "Request body must contain the token" });
  }

  const user = await getAuthenticatedUser(req, "authorized");

  if (user === null) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    if (user.otp_enabled) {
      const log = parseLog(req, `User ${user.id} - OTP must not be verified`);
      logger.warn(log.message, log.data);

      return res.status(422).json({ error: "OTP must not be verified" });
    }

    if (user.otp_secret === null) {
      const log = parseLog(req, `User ${user.id} - OTP must be generated`);
      logger.warn(log.message, log.data);

      return res.status(422).json({ error: "OTP must be generated" });
    }

    const { token } = req.body;

    if (!validOtp(token)) {
      const log = parseLog(req, `User ${user.id} - Invalid token`);
      logger.warn(log.message, log.data);

      return res.status(422).json({ error: "Invalid token" });
    }

    const totp = new OTPAuth.TOTP({
      issuer: "tcc-banking-application.com",
      label: "TCC Banking Application",
      algorithm: "SHA1",
      digits: 6,
      secret: CryptoJS.AES.decrypt(
        user.otp_secret,
        TOTP_SECRET_ENCRYPTION_KEY
      ).toString(CryptoJS.enc.Utf8),
    });

    if (totp.validate({ token: token, window: 1 }) === null) {
      const log = parseLog(req, `User ${user.id} - Wrong token`);
      logger.warn(log.message, log.data);

      return res.status(401).json({ error: "Wrong token" });
    }

    await prisma.user.update({
      where: { id: user.id },
      data: { otp_enabled: true },
    });

    const log = parseLog(req, `User ${user.id} - OTP verified`);
    logger.info(log.message, log.data);

    return res.status(200).json({
      token: jwt.sign({ userId: user.id, authorized: true }, JWT_SECRET, {
        expiresIn: "15m",
      }),
    });
  } catch (error) {
    const log = parseErrorLog(req, error);
    logger.error(log.message, log.data);

    res.status(500).json({ error: "Internal server error" });
  }
}

function otpSecretGenerate() {
  const secret = pkg
    .encode(crypto.randomBytes(15))
    .replace(/=/g, "")
    .substring(0, 24);
  return secret;
}
