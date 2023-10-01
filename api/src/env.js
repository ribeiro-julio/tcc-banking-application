// app
export const PORT = parseInt(process.env.PORT) || -1;

// database
export const DEFAULT_USER_PASSWORD = process.env.DEFAULT_USER_PASSWORD || "";
export const DEFAULT_USER_PIN = process.env.DEFAULT_USER_PIN || "";

// encryption
export const TOTP_SECRET_ENCRYPTION_KEY =
  process.env.TOTP_SECRET_ENCRYPTION_KEY || "";

// jwt
export const JWT_SECRET = process.env.JWT_SECRET || "";
