import bcrypt from "bcrypt";
import { PrismaClient } from "@prisma/client";

import { JWT_SECRET } from "../env.js";
import { logger, parseErrorLog, parseLog } from "../logger.js";
import { validAmount, validEmail, validPin } from "../helpers/validators.js";

const prisma = new PrismaClient();

export async function transferMoney(req, res) {
  if (
    Object.keys(req.body).length !== 3 ||
    !req.body.hasOwnProperty("amount") ||
    !req.body.hasOwnProperty("destination") ||
    !req.body.hasOwnProperty("pin") ||
    typeof req.body.amount !== "string" ||
    typeof req.body.destination !== "string" ||
    typeof req.body.pin !== "string"
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
    const { amount, destination, pin } = req.body;

    if (!validAmount(amount) || !validEmail(destination) || !validPin(pin)) {
      const log = parseLog(req, `Invalid inputs`);
      logger.warn(log.message, log.data);

      return res.status(422).json({
        error: "Invalid inputs",
      });
    }

    if (!(await bcrypt.compare(pin, user.pin))) {
      const log = parseLog(req, `Wrong pin`);
      logger.warn(log.message, log.data);

      return res.status(403).json({
        error: "Forbidden",
      });
    }

    if (user.balance - amount < 0) {
      const log = parseLog(req, `Insufficient balance`);
      logger.warn(log.message, log.data);

      return res.status(422).json({
        error: "Insufficient balance",
      });
    }

    const destinationUser = await prisma.user.findUnique({
      where: { id: destination },
    });

    if (destinationUser === null) {
      const log = parseLog(req, `Destination not found`);
      logger.warn(log.message, log.data);

      return res.status(422).json({
        error: "Destination not found",
      });
    }

    await prisma.$transaction(async (tx) => {
      await tx.account.update({
        data: { balance: { decrement: Number(amount) } },
        where: { email: user.email },
      });

      await tx.account.update({
        data: { balance: { increment: Number(amount) } },
        where: { email: destinationUser.email },
      });
    });

    return res.status(200).json({
      confirmation: {
        amount: amount,
        destination: {
          name: destinationUser.name,
          email: destinationUser.email,
        },
        origin: { name: user.name, email: user.email },
      },
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
