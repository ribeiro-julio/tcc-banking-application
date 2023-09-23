import crypto from "crypto";
import CryptoJS from "crypto-js";
import pkg from "hi-base32";
import jwt from "jsonwebtoken";
import * as OTPAuth from "otpauth";
import { PrismaClient } from "@prisma/client";

import { JWT_SECRET, TOTP_SECRET_ENCRYPTION_KEY } from "../env.js";
import { logger, parseErrorLog, parseLog } from "../logger.js";

const prisma = new PrismaClient();

export async function otpDisableController(req, res) {
  if (Object.keys(req.body).length !== 0) {
    const log = parseLog(req, `Failed disable OTP attempt with bad request`);
    logger.warn(log.message, log.data);

    return res.status(400).json({
      error: "Bad request",
    });
  }

  try {
    const authHeader = req.get("Authorization");
    if (!authHeader || !authHeader.includes("Bearer ")) {
      const log = parseLog(
        req,
        `Failed disable OTP attempt with missing authorization token`
      );
      logger.warn(log.message, log.data);

      return res.status(401).json({
        error: "Unauthorized",
      });
    }

    let session = { userId: null, otpEnabled: false, authorized: false };
    jwt.verify(
      authHeader.replace("Bearer ", ""),
      JWT_SECRET,
      (error, decoded) => {
        if (!error) {
          session = {
            userId: decoded.userId,
            otpEnabled: decoded.otpEnabled,
            authorized: decoded.authorized,
          };
        }
      }
    );

    if (session.userId === null || !session.otpEnabled || !session.authorized) {
      const log = parseLog(
        req,
        `Failed disable OTP attempt with invalid authorization token`
      );
      logger.warn(log.message, log.data);

      return res.status(401).json({
        error: "Unauthorized",
      });
    }

    const user = await prisma.user.findUnique({
      where: { id: session.userId },
    });

    if (user === null) {
      const log = parseLog(
        req,
        `Failed disable OTP attempt with invalid user ${session.userId}`
      );
      logger.warn(log.message, log.data);

      return res.status(401).json({
        error: "Unauthorized",
      });
    }

    if (!user.otp_enabled || user.otp_secret === null) {
      const log = parseLog(
        req,
        `Failed disable OTP attempt with user ${session.userId} without active OTP`
      );
      logger.warn(log.message, log.data);

      return res.status(401).json({
        error: "Unauthorized",
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

    return res.status(200).json({
      token: jwt.sign(
        { userId: user.id, otpEnabled: false, authorized: true },
        JWT_SECRET,
        { expiresIn: "30m" }
      ),
    });
  } catch (error) {
    const log = parseErrorLog(req, error);
    logger.error(log.message, log.data);

    res.status(500).json({
      error: "Internal Server Error",
    });
  }
}

export async function otpGenerateController(req, res) {
  if (Object.keys(req.body).length !== 0) {
    const log = parseLog(req, `Failed OTP generate attempt with bad request`);
    logger.warn(log.message, log.data);

    return res.status(400).json({
      error: "Bad request",
    });
  }

  try {
    const authHeader = req.get("Authorization");
    if (!authHeader || !authHeader.includes("Bearer ")) {
      const log = parseLog(
        req,
        `Failed OTP generate attempt with missing authorization token`
      );
      logger.warn(log.message, log.data);

      return res.status(401).json({
        error: "Unauthorized",
      });
    }

    let session = { userId: null, otpEnabled: true, authorized: false };
    jwt.verify(
      authHeader.replace("Bearer ", ""),
      JWT_SECRET,
      (error, decoded) => {
        if (!error) {
          session = {
            userId: decoded.userId,
            otpEnabled: decoded.otpEnabled,
            authorized: decoded.authorized,
          };
        }
      }
    );

    if (session.userId === null || session.otpEnabled || !session.authorized) {
      const log = parseLog(
        req,
        `Failed OTP generate attempt with invalid authorization token`
      );
      logger.warn(log.message, log.data);

      return res.status(401).json({
        error: "Unauthorized",
      });
    }

    const user = await prisma.user.findUnique({
      where: { id: session.userId },
    });

    if (user === null) {
      const log = parseLog(
        req,
        `Failed OTP generate attempt with invalid user ${session.userId}`
      );
      logger.warn(log.message, log.data);

      return res.status(401).json({
        error: "Unauthorized",
      });
    }

    if (user.otp_enabled || user.otp_secret !== null) {
      const log = parseLog(
        req,
        `Failed OTP generate attempt for user ${session.userId} with OTP already configured`
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
      error: "Internal Server Error",
    });
  }
}

export async function otpValidateController(req, res) {
  if (
    Object.keys(req.body).length !== 1 ||
    !req.body.hasOwnProperty("token") ||
    typeof req.body.token !== "string"
  ) {
    const log = parseLog(req, `Failed OTP validate attempt with bad request`);
    logger.warn(log.message, log.data);

    return res.status(400).json({
      error: "Bad request",
    });
  }

  try {
    const authHeader = req.get("Authorization");
    if (!authHeader || !authHeader.includes("Bearer ")) {
      const log = parseLog(
        req,
        `Failed OTP validate attempt with missing authorization token`
      );
      logger.warn(log.message, log.data);

      return res.status(401).json({
        error: "Unauthorized",
      });
    }

    let session = { userId: null, otpEnabled: false, authorized: true };
    jwt.verify(
      authHeader.replace("Bearer ", ""),
      JWT_SECRET,
      (error, decoded) => {
        if (!error) {
          session = {
            userId: decoded.userId,
            otpEnabled: decoded.otpEnabled,
            authorized: decoded.authorized,
          };
        }
      }
    );

    if (session.userId === null || !session.otpEnabled || session.authorized) {
      const log = parseLog(
        req,
        `Failed OTP validate attempt with invalid authorization token`
      );
      logger.warn(log.message, log.data);

      return res.status(401).json({
        error: "Unauthorized",
      });
    }

    const user = await prisma.user.findUnique({
      where: { id: session.userId },
    });

    if (user === null) {
      const log = parseLog(
        req,
        `Failed OTP validate attempt with invalid user ${session.userId}`
      );
      logger.warn(log.message, log.data);

      return res.status(401).json({
        error: "Unauthorized",
      });
    }

    if (!user.otp_enabled || user.otp_secret === null) {
      const log = parseLog(
        req,
        `Failed OTP validate attempt for user ${session.userId} without active OTP`
      );
      logger.warn(log.message, log.data);

      return res.status(401).json({
        error: "Unauthorized",
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

    if (totp.validate({ token: req.body.token, window: 1 }) === null) {
      const log = parseLog(
        req,
        `Failed OTP validate attempt for user ${session.userId} with invalid token`
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
      token: jwt.sign(
        { userId: user.id, otpEnabled: true, authorized: true },
        JWT_SECRET,
        { expiresIn: "30m" }
      ),
    });
  } catch (error) {
    const log = parseErrorLog(req, error);
    logger.error(log.message, log.data);

    res.status(500).json({
      error: "Internal Server Error",
    });
  }
}

export async function otpVerifyController(req, res) {
  if (
    Object.keys(req.body).length !== 1 ||
    !req.body.hasOwnProperty("token") ||
    typeof req.body.token !== "string"
  ) {
    const log = parseLog(req, `Failed OTP verify attempt with bad request`);
    logger.warn(log.message, log.data);

    return res.status(400).json({
      error: "Bad request",
    });
  }

  try {
    const authHeader = req.get("Authorization");
    if (!authHeader || !authHeader.includes("Bearer ")) {
      const log = parseLog(
        req,
        `Failed OTP verify attempt with missing authorization token`
      );
      logger.warn(log.message, log.data);

      return res.status(401).json({
        error: "Unauthorized",
      });
    }

    let session = { userId: null, otpEnabled: true, authorized: false };
    jwt.verify(
      authHeader.replace("Bearer ", ""),
      JWT_SECRET,
      (error, decoded) => {
        if (!error) {
          session = {
            userId: decoded.userId,
            otpEnabled: decoded.otpEnabled,
            authorized: decoded.authorized,
          };
        }
      }
    );

    if (session.userId === null || session.otpEnabled || !session.authorized) {
      const log = parseLog(
        req,
        `Failed OTP verify attempt with invalid authorization token`
      );
      logger.warn(log.message, log.data);

      return res.status(401).json({
        error: "Unauthorized",
      });
    }

    const user = await prisma.user.findUnique({
      where: { id: session.userId },
    });

    if (user === null) {
      const log = parseLog(
        req,
        `Failed OTP verify attempt with invalid user ${session.userId}`
      );
      logger.warn(log.message, log.data);

      return res.status(401).json({
        error: "Unauthorized",
      });
    }

    if (user.otp_enabled || user.otp_secret === null) {
      const log = parseLog(
        req,
        `Failed OTP verify attempt for user ${session.userId} without active OTP`
      );
      logger.warn(log.message, log.data);

      return res.status(401).json({
        error: "Unauthorized",
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

    if (totp.validate({ token: req.body.token, window: 1 }) === null) {
      const log = parseLog(
        req,
        `Failed OTP verify attempt for user ${session.userId} with invalid token`
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
      token: jwt.sign(
        { userId: user.id, otpEnabled: true, authorized: true },
        JWT_SECRET,
        { expiresIn: "30m" }
      ),
    });
  } catch (error) {
    const log = parseErrorLog(req, error);
    logger.error(log.message, log.data);

    res.status(500).json({
      error: "Internal Server Error",
    });
  }
}

function otpSecretGenerate() {
  const secret = pkg
    .encode(crypto.randomBytes(15))
    .replace(/=/g, "")
    .substring(0, 24);
  return secret;
}
