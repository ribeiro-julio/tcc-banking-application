import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { PrismaClient } from "@prisma/client";

import { JWT_SECRET } from "../env.js";
import { logger, parseErrorLog, parseLog } from "../logger.js";
import { validPassword, validPin } from "../helpers/validators.js";

const prisma = new PrismaClient();

export async function getMeController(req, res) {
  if (Object.keys(req.body).length !== 0) {
    const log = parseLog(req, "Bad request");
    logger.warn(log.message, log.data);

    return res.status(400).json({
      error: "Request body must be empty",
    });
  }

  const user = await getAuthenticatedUser(req);

  if (user === null) {
    return res.status(401).json({
      error: "Unauthorized",
    });
  }

  return res.status(200).json({ name: user.name, balance: user.balance });
}

export async function patchPasswordController(req, res) {
  if (
    Object.keys(req.body).length !== 3 ||
    !req.body.hasOwnProperty("oldPassword") ||
    !req.body.hasOwnProperty("newPassword") ||
    !req.body.hasOwnProperty("newPasswordConfirmation") ||
    typeof req.body.oldPassword !== "string" ||
    typeof req.body.newPassword !== "string" ||
    typeof req.body.newPasswordConfirmation !== "string"
  ) {
    const log = parseLog(req, "Bad request");
    logger.warn(log.message, log.data);

    return res.status(400).json({
      error: "Request body must contain the new password",
    });
  }

  const user = await getAuthenticatedUser(req);

  if (user === null) {
    return res.status(401).json({
      error: "Unauthorized",
    });
  }

  try {
    const { oldPassword, newPassword, newPasswordConfirmation } = req.body;

    if (!(await bcrypt.compare(oldPassword, user.password))) {
      const log = parseLog(
        req,
        `Patch password attempt with incorrect current password for user ${user.id}`
      );
      logger.warn(log.message, log.data);

      return res.status(401).json({
        error: "Incorrect current password",
      });
    }

    if (!validPassword(newPassword)) {
      const log = parseLog(req, "Invalid password");
      logger.warn(log.message, log.data);

      return res.status(422).json({
        error: "Invalid password",
      });
    }

    if (newPassword !== newPasswordConfirmation) {
      const log = parseLog(req, "Invalid password confirmation");
      logger.warn(log.message, log.data);

      return res.status(422).json({
        error: "Invalid password confirmation",
      });
    }

    await prisma.user.update({
      data: { password: await bcrypt.hash(newPassword, 10) },
      where: { id: user.id },
    });

    const log = parseLog(req, `Successfully patched user ${user.id} password`);
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

export async function patchPinController(req, res) {
  if (
    Object.keys(req.body).length !== 3 ||
    !req.body.hasOwnProperty("oldPin") ||
    !req.body.hasOwnProperty("newPin") ||
    !req.body.hasOwnProperty("newPinConfirmation") ||
    typeof req.body.oldPin !== "string" ||
    typeof req.body.newPin !== "string" ||
    typeof req.body.newPinConfirmation !== "string"
  ) {
    const log = parseLog(req, "Bad request");
    logger.warn(log.message, log.data);

    return res.status(400).json({
      error: "Request body must contain the new PIN",
    });
  }

  const user = await getAuthenticatedUser(req);

  if (user === null) {
    return res.status(401).json({
      error: "Unauthorized",
    });
  }

  try {
    const { oldPin, newPin, newPinConfirmation } = req.body;

    if (!(await bcrypt.compare(oldPin, user.pin))) {
      const log = parseLog(
        req,
        `Patch PIN attempt with incorrect current PIN for user ${user.id}`
      );
      logger.warn(log.message, log.data);

      return res.status(401).json({
        error: "Incorrect current PIN",
      });
    }

    if (!validPin(newPin)) {
      const log = parseLog(req, "Invalid PIN");
      logger.warn(log.message, log.data);

      return res.status(422).json({
        error: "Invalid PIN",
      });
    }

    if (newPin !== newPinConfirmation) {
      const log = parseLog(req, "Invalid PIN confirmation");
      logger.warn(log.message, log.data);

      return res.status(422).json({
        error: "Invalid PIN confirmation",
      });
    }

    await prisma.user.update({
      data: { pin: await bcrypt.hash(newPin, 10) },
      where: { id: user.id },
    });

    const log = parseLog(req, `Successfully patched user ${user.id} PIN`);
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

async function getAuthenticatedUser(req) {
  try {
    const authHeader = req.get("Authorization");

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
