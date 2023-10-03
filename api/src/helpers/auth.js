import { PrismaClient } from "@prisma/client";
import jwt from "jsonwebtoken";

import { JWT_SECRET } from "../env.js";
import { parseLog, logger, parseErrorLog } from "../logger.js";

export async function getAuthenticatedUser(req, method) {
  try {
    const prisma = new PrismaClient();

    const authHeader = req.get("Authorization");

    if (!authHeader || !authHeader.includes("Bearer ")) {
      const log = parseLog(req, "Missing JWT");
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

    if (session.userId === null) {
      const log = parseLog(req, "Invalid JWT");
      logger.warn(log.message, log.data);

      return null;
    }

    if (method === "authorized" && !session.authorized) {
      const log = parseLog(req, `Invalid JWT`);
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
