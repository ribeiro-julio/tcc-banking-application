import crypto from "crypto";
import CryptoJS from "crypto-js";
import pkg from "hi-base32";
import jwt from "jsonwebtoken";
import * as OTPAuth from "otpauth";
import { PrismaClient } from "@prisma/client";

import { JWT_SECRET, TOTP_SECRET_ENCRYPTION_KEY } from "../env.js";
import { logger, parseErrorLog, parseLog } from "../logger.js";
import { validOtp } from "../helpers/validators.js";

const prisma = new PrismaClient();

export async function otpDisableController(req, res) {
  if (Object.keys(req.body).length !== 0) {
    const log = parseLog(req, `Bad request`);
    logger.warn(log.message, log.data);

    return res.status(400).json({
      error: "Bad request",
    });
  }

  const user = await getAuthenticatedUser(req.get("Authorization"));

  if (user === null) {
    return res.status(401).json({
      error: "Unauthorized",
    });
  }

  try {
    if (!user.otp_enabled || user.otp_secret === null) {
      const log = parseLog(req, `User ${session.userId} without active OTP`);
      logger.warn(log.message, log.data);

      return res.status(400).json({
        error: "User without active OTP",
      });
    }

    await prisma.user.update({
      where: { id: session.userId },
      data: {
        otp_enabled: false,
        otp_secret: null,
      },
    });

    const log = parseLog(req, `Successfull disable OTP for user ${user.id}`);
    logger.info(log.message, log.data);

    return res.status(200).json({ message: "Success" });
  } catch (error) {
    const log = parseErrorLog(req, error);
    logger.error(log.message, log.data);

    res.status(500).json({
      error: "Internal server error",
    });
  }
}

export async function otpGenerateController(req, res) {
  if (Object.keys(req.body).length !== 0) {
    const log = parseLog(req, `Bad request`);
    logger.warn(log.message, log.data);

    return res.status(400).json({
      error: "Bad request",
    });
  }

  const user = await getAuthenticatedUser(req.get("Authorization"));

  if (user === null) {
    return res.status(401).json({
      error: "Unauthorized",
    });
  }

  try {
    if (user.otp_enabled || user.otp_secret !== null) {
      const log = parseLog(
        req,
        `User ${session.userId} with OTP already configured`
      );
      logger.warn(log.message, log.data);

      return res.status(401).json({
        error: "Unauthorized",
      });
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
      where: { id: session.userId },
      data: {
        otp_secret: CryptoJS.AES.encrypt(
          otpSecret,
          TOTP_SECRET_ENCRYPTION_KEY
        ).toString(),
      },
    });

    const log = parseLog(
      req,
      `Successful generate OTP for user ${session.userId}`
    );
    logger.info(log.message, log.data);

    return res.status(200).json({ url: totp.toString(), secret: otpSecret });
  } catch (error) {
    const log = parseErrorLog(req, error);
    logger.error(log.message, log.data);

    res.status(500).json({
      error: "Internal server error",
    });
  }
}

export async function otpValidateController(req, res) {
  if (
    Object.keys(req.body).length !== 1 ||
    !req.body.hasOwnProperty("token") ||
    typeof req.body.token !== "string"
  ) {
    const log = parseLog(req, `Bad request`);
    logger.warn(log.message, log.data);

    return res.status(400).json({
      error: "Bad request",
    });
  }

  const user = await getAuthenticatedUser(req.get("Authorization"));

  if (user === null) {
    return res.status(401).json({
      error: "Unauthorized",
    });
  }

  try {
    if (!user.otp_enabled || user.otp_secret === null) {
      const log = parseLog(req, `User ${session.userId} without active OTP`);
      logger.warn(log.message, log.data);

      return res.status(401).json({
        error: "Unauthorized",
      });
    }

    const { token } = req.body;

    if (!validOtp(token)) {
      const log = parseLog(req, `Invalid inputs`);
      logger.warn(log.message, log.data);

      return res.status(422).json({
        error: "Invalid inputs",
      });
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
      const log = parseLog(
        req,
        `User ${session.userId} with invalid OTP token`
      );
      logger.warn(log.message, log.data);

      return res.status(401).json({
        error: "Unauthorized",
      });
    }

    const log = parseLog(
      req,
      `Successful validate OTP for user ${session.userId}`
    );
    logger.info(log.message, log.data);

    return res.status(200).json({
      token: jwt.sign({ userId: user.id, authorized: true }, JWT_SECRET, {
        expiresIn: "30m",
      }),
    });
  } catch (error) {
    const log = parseErrorLog(req, error);
    logger.error(log.message, log.data);

    res.status(500).json({
      error: "Internal server error",
    });
  }
}

export async function otpVerifyController(req, res) {
  if (
    Object.keys(req.body).length !== 1 ||
    !req.body.hasOwnProperty("token") ||
    typeof req.body.token !== "string"
  ) {
    const log = parseLog(req, `Bad request`);
    logger.warn(log.message, log.data);

    return res.status(400).json({
      error: "Bad request",
    });
  }

  const user = await getAuthenticatedUser(req.get("Authorization"));

  if (user === null) {
    return res.status(401).json({
      error: "Unauthorized",
    });
  }

  try {
    if (user.otp_enabled || user.otp_secret === null) {
      const log = parseLog(req, `User ${session.userId} without active OTP`);
      logger.warn(log.message, log.data);

      return res.status(401).json({
        error: "Unauthorized",
      });
    }

    const { token } = req.body;

    if (!validOtp(token)) {
      const log = parseLog(req, `Invalid inputs`);
      logger.warn(log.message, log.data);

      return res.status(422).json({
        error: "Invalid inputs",
      });
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
      const log = parseLog(
        req,
        `User ${session.userId} with invalid OTP token`
      );
      logger.warn(log.message, log.data);

      return res.status(401).json({
        error: "Unauthorized",
      });
    }

    await prisma.user.update({
      where: { id: session.userId },
      data: { otp_enabled: true },
    });

    const log = parseLog(
      req,
      `Successful verify OTP for user ${session.userId}`
    );
    logger.info(log.message, log.data);

    return res.status(200).json({
      token: jwt.sign({ userId: user.id, authorized: true }, JWT_SECRET, {
        expiresIn: "30m",
      }),
    });
  } catch (error) {
    const log = parseErrorLog(req, error);
    logger.error(log.message, log.data);

    res.status(500).json({
      error: "Internal server error",
    });
  }
}

async function getAuthenticatedUser(authHeader) {
  try {
    if (!authHeader || !authHeader.includes("Bearer ")) {
      const log = parseLog(req, `Missing authorization token`);
      logger.warn(log.message, log.data);

      return null;
    }

    let session = { userId: null, authorized: false };
    jwt.verify(
      authHeader.replace("Bearer ", ""),
      JWT_SECRET,
      (error, decoded) => {
        if (!error) {
          session = {
            userId: decoded.userId,
            authorized: decoded.authorized,
          };
        }
      }
    );

    if (session.userId === null || !session.authorized) {
      const log = parseLog(req, `Invalid authorization token`);
      logger.warn(log.message, log.data);

      return null;
    }

    const user = await prisma.user.findUnique({
      where: { id: session.userId },
    });

    if (user === null) {
      const log = parseLog(req, `Invalid user ${session.userId}`);
      logger.warn(log.message, log.data);

      return null;
    }

    return user;
  } catch (error) {
    const log = parseErrorLog(req, error);
    logger.error(log.message, log.data);
  }

  return null;
}

function otpSecretGenerate() {
  const secret = pkg
    .encode(crypto.randomBytes(15))
    .replace(/=/g, "")
    .substring(0, 24);
  return secret;
}
