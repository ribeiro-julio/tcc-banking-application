import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

import { validLoginRequestBody, validEmail } from "../helpers/validators.js";
import { logger, parseErrorLog, parseLog } from "../logger.js";
import { JWT_SECRET } from "../env.js";

export async function loginController(req, res) {
  if (!validLoginRequestBody(req)) {
    return res
      .status(400)
      .json({ error: "Request body must contain the email and password" });
  }

  try {
    const prisma = new PrismaClient();

    const { email, password } = req.body;

    if (!validEmail(email)) {
      const log = parseLog(req, "Invalid email");
      logger.warn(log.message, log.data);

      return res.status(422).json({ error: "Invalid email" });
    }

    const user = await prisma.user.findUnique({ where: { email: email } });

    if (user === null) {
      const log = parseLog(req, `Incorrect email ${email}`);
      logger.warn(log.message, log.data);

      return res.status(401).json({ error: "Incorrect email or password" });
    }

    if (!(await bcrypt.compare(password, user.password))) {
      const log = parseLog(req, `User ${user.id} - Incorrect password`);
      logger.warn(log.message, log.data);

      return res.status(401).json({ error: "Incorrect email or password" });
    }

    const log = parseLog(req, `User ${user.id} - Logged in`);
    logger.info(log.message, log.data);

    let authorized = true;
    if (user.otp_enabled) authorized = false;

    return res.status(200).json({
      token: jwt.sign({ userId: user.id, authorized }, JWT_SECRET, {
        expiresIn: "15m",
      }),
    });
  } catch (error) {
    const log = parseErrorLog(req, error);
    logger.error(log.message, log.data);

    res.status(500).json({ error: "Internal server error" });
  }
}
