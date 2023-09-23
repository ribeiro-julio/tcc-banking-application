import winston from "winston";

const { combine, timestamp, json } = winston.format;

export const logger = winston.createLogger({
  level: "info",
  format: combine(
    timestamp({
      format: "DD-MM-YYYY HH:mm:ss",
    }),
    json()
  ),
  transports: [
    new winston.transports.File({ filename: "logs/application.log" }),
  ],
});

export function parseErrorLog(req, error) {
  return {
    message: `Unhandled exception: ${error.message}`,
    data: {
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      url: req.originalUrl,
      method: req.method,
      stack: error.stack,
    },
  };
}

export function parseLog(req, message) {
  return {
    message: message,
    data: {
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      url: req.originalUrl,
      method: req.method,
    },
  };
}
