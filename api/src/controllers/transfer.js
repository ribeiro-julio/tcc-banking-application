import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";

import {
  validTransferRequestBody,
  validAmount,
  validEmail,
  validPin,
} from "../helpers/validators.js";
import { parseLog, logger, parseErrorLog } from "../logger.js";
import { getAuthenticatedUser } from "../helpers/auth.js";

export async function transferMoney(req, res) {
  if (!validTransferRequestBody(req)) {
    const log = parseLog(
      req,
      "Request body must contain only the amount, destination and PIN"
    );
    logger.warn(log.message, log.data);

    return res.status(400).json({
      error: "Request body must contain only the amount, destination and PIN",
    });
  }

  const user = await getAuthenticatedUser(req, "authorized");

  if (user === null) return res.status(401).json({ error: "Unauthorized" });

  try {
    const prisma = new PrismaClient();

    const { amount, destination, pin } = req.body;

    if (!validAmount(amount)) {
      const log = parseLog(req, `User ${user.id} - Invalid amount`);
      logger.warn(log.message, log.data);

      return res.status(422).json({ error: "Invalid amount" });
    }

    if (!validEmail(destination)) {
      const log = parseLog(req, `User ${user.id} - Invalid destination`);
      logger.warn(log.message, log.data);

      return res.status(422).json({ error: "Invalid destination" });
    }

    if (!validPin(pin)) {
      const log = parseLog(req, `User ${user.id} - Invalid PIN`);
      logger.warn(log.message, log.data);

      return res.status(422).json({ error: "Invalid PIN" });
    }

    if (user.balance - Number(amount) < 0) {
      const log = parseLog(req, `User ${user.id} - Insufficient balance`);
      logger.warn(log.message, log.data);

      return res.status(422).json({ error: "Insufficient balance" });
    }

    if (user.email === destination) {
      const log = parseLog(
        req,
        `User ${user.id} - Destination must be different than the origin`
      );
      logger.warn(log.message, log.data);

      return res
        .status(422)
        .json({ error: "Destination must be different than the origin" });
    }

    if (destinationUser === null) {
      const log = parseLog(req, `User ${user.id} - Destination not found`);
      logger.warn(log.message, log.data);

      return res.status(422).json({ error: "Destination not found" });
    }

    if (!(await bcrypt.compare(pin, user.pin))) {
      const log = parseLog(req, `User ${user.id} - Wrong PIN`);
      logger.warn(log.message, log.data);

      return res.status(403).json({ error: "Wrong PIN" });
    }

    const destinationUser = await prisma.user.findUnique({
      where: { email: destination },
    });

    await prisma.$transaction(async (tx) => {
      await tx.user.update({
        data: { balance: { decrement: Number(amount) } },
        where: { email: user.email },
      });

      await tx.user.update({
        data: { balance: { increment: Number(amount) } },
        where: { email: destinationUser.email },
      });
    });

    return res.status(200).json({
      confirmation: {
        origin: { name: user.name, email: user.email },
        destination: {
          name: destinationUser.name,
          email: destinationUser.email,
        },
        amount: amount,
      },
    });
  } catch (error) {
    const log = parseErrorLog(req, error);
    logger.error(log.message, log.data);

    res.status(500).json({ error: "Internal server error" });
  }
}
