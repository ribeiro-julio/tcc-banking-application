import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { logger, parseErrorLog, parseLog } from "../logger.js";
import { PrismaClient } from "@prisma/client";

import { JWT_SECRET } from "../env.js";
import { validEmail, validPassword } from "../helpers/validators.js";

const prisma = new PrismaClient();

export async function loginController(req, res) {
  if (
    Object.keys(req.body).length !== 2 ||
    !req.body.hasOwnProperty("email") ||
    !req.body.hasOwnProperty("password") ||
    typeof req.body.email !== "string" ||
    typeof req.body.password !== "string"
  ) {
    const log = parseLog(req, "Bad request");
    logger.warn(log.message, log.data);

    return res.status(400).json({
      error: "Request body must contain only the email and password",
    });
  }

  try {
    const { email, password } = req.body;

    if (!validEmail(email)) {
      const log = parseLog(req, "Invalid email");
      logger.warn(log.message, log.data);

      return res.status(422).json({
        error: "Invalid email",
      });
    }

    const user = await prisma.user.findUnique({ where: { email: email } });

    if (user === null) {
      const log = parseLog(req, `Failed login attempt with email ${email}`);
      logger.warn(log.message, log.data);

      return res.status(401).json({
        error: "Incorrect email or password",
      });
    }

    if (!(await bcrypt.compare(password, user.password))) {
      const log = parseLog(req, `Failed login attempt with email ${email}`);
      logger.warn(log.message, log.data);

      return res.status(401).json({
        error: "Incorrect email or password",
      });
    }

    const log = parseLog(req, `Successful login for user ${user.id}`);
    logger.info(log.message, log.data);

    let authorized = true;
    if (user.otp_enabled) {
      authorized = false;
    }

    return res.status(200).json({
      token: jwt.sign({ userId: user.id, authorized }, JWT_SECRET, {
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
