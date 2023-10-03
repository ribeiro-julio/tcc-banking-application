import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";

import {
  requestHasEmptyBody,
  validPatchPasswordRequestBody,
  validPassword,
  validPatchPinRequestBody,
  validPin,
} from "../helpers/validators.js";
import { getAuthenticatedUser } from "../helpers/auth.js";
import { parseLog, logger, parseErrorLog } from "../logger.js";

export async function getMeController(req, res) {
  if (!requestHasEmptyBody(req)) {
    return res.status(400).json({ error: "Request body must be empty" });
  }

  const user = await getAuthenticatedUser(req, "authorized");

  if (user === null) return res.status(401).json({ error: "Unauthorized" });

  return res.status(200).json({ name: user.name, balance: user.balance });
}

export async function patchPasswordController(req, res) {
  if (!validPatchPasswordRequestBody(req)) {
    return res.status(400).json({
      error:
        "Request body must contain only the oldPassword, newPassword and newPasswordConfirmation",
    });
  }

  const user = await getAuthenticatedUser(req);

  if (user === null) return res.status(401).json({ error: "Unauthorized" });

  try {
    const prisma = new PrismaClient();

    const { oldPassword, newPassword, newPasswordConfirmation } = req.body;

    if (!(await bcrypt.compare(oldPassword, user.password))) {
      const log = parseLog(req, `User ${user.id} - Wrong current password`);
      logger.warn(log.message, log.data);

      return res.status(403).json({ error: "Wrong current password" });
    }

    if (!validPassword(newPassword)) {
      const log = parseLog(req, `User ${user.id} - Invalid password`);
      logger.warn(log.message, log.data);

      return res.status(422).json({ error: "Invalid password" });
    }

    if (newPassword !== newPasswordConfirmation) {
      const log = parseLog(
        req,
        `User ${user.id} - Wrong password confirmation`
      );
      logger.warn(log.message, log.data);

      return res.status(422).json({ error: "Wrong password confirmation" });
    }

    await prisma.user.update({
      data: { password: await bcrypt.hash(newPassword, 10) },
      where: { id: user.id },
    });

    const log = parseLog(req, `User ${user.id} - Password patched`);
    logger.info(log.message, log.data);

    return res.status(200).json({ message: "Success" });
  } catch (error) {
    const log = parseErrorLog(req, error);
    logger.error(log.message, log.data);

    res.status(500).json({ error: "Internal server error" });
  }
}

export async function patchPinController(req, res) {
  if (!validPatchPinRequestBody(req)) {
    return res.status(400).json({
      error:
        "Request body must contain only the oldPin, newPin and newPinConfirmation",
    });
  }

  const user = await getAuthenticatedUser(req);

  if (user === null) return res.status(401).json({ error: "Unauthorized" });

  try {
    const prisma = new PrismaClient();

    const { oldPin, newPin, newPinConfirmation } = req.body;

    if (!(await bcrypt.compare(oldPin, user.pin))) {
      const log = parseLog(req, `User ${user.id} - Wrong current PIN`);
      logger.warn(log.message, log.data);

      return res.status(403).json({ error: "Wrong current PIN" });
    }

    if (!validPin(newPin)) {
      const log = parseLog(req, `User ${user.id} - Invalid PIN`);
      logger.warn(log.message, log.data);

      return res.status(422).json({ error: "Invalid PIN" });
    }

    if (newPin !== newPinConfirmation) {
      const log = parseLog(req, `User ${user.id} - Wrong PIN confirmation`);
      logger.warn(log.message, log.data);

      return res.status(422).json({ error: "Wrong PIN confirmation" });
    }

    await prisma.user.update({
      data: { pin: await bcrypt.hash(newPin, 10) },
      where: { id: user.id },
    });

    const log = parseLog(req, `User ${user.id} - PIN patched`);
    logger.info(log.message, log.data);

    return res.status(200).json({ message: "Success" });
  } catch (error) {
    const log = parseErrorLog(req, error);
    logger.error(log.message, log.data);

    res.status(500).json({ error: "Internal server error" });
  }
}
