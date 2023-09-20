import bcrypt from "bcrypt";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

// practices:
//  - validate inputs
//  - remove information from error messages
//  - handle exceptions
// TODO: JWT, 2FA, rate limit
export async function login(req, res) {
  if (
    Object.keys(req.body).length !== 2 ||
    !req.body.hasOwnProperty("email") ||
    !req.body.hasOwnProperty("password") ||
    typeof req.body.email !== "string" ||
    typeof req.body.password !== "string"
  ) {
    return res.status(400).json({
      error: "Bad request",
    });
  }

  try {
    const { email, password } = req.body;

    const user = await prisma.user.findUnique({ where: { email: email } });

    if (!user) {
      return res.status(401).json({
        error: "Incorrect email or password",
      });
    }

    if (!(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        error: "Incorrect email or password",
      });
    }

    res.status(200).json({ message: "OK" });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      error: "Internal server error",
    });
  }
}
