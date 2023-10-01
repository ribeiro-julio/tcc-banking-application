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

export async function patchMeController(req, res) {}

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
