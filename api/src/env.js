// app
export const PORT = parseInt(process.env.PORT) || -1;

// encryption
export const TOTP_SECRET_ENCRYPTION_KEY =
  process.env.TOTP_SECRET_ENCRYPTION_KEY || "";

// jwt
export const JWT_SECRET = process.env.JWT_SECRET || "";
