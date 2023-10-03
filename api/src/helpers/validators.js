export function requestHasEmptyBody(req) {
  if (Object.keys(req.body).length !== 0) {
    const log = parseLog(req, "Request body must be empty");
    logger.warn(log.message, log.data);

    return false;
  }

  return true;
}

export function requestHasTokenOnBody(req) {
  if (
    Object.keys(req.body).length !== 1 ||
    !req.body.hasOwnProperty("token") ||
    typeof req.body.token !== "string"
  ) {
    const log = parseLog(req, "Request body must contain the token");
    logger.warn(log.message, log.data);

    return false;
  }

  return true;
}

export function validAmount(amount) {
  const regex = /^[1-9][0-9]*$/;
  return regex.test(amount);
}

export function validEmail(email) {
  const regex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z.]{2,}$/;
  return regex.test(email);
}

export function validOtp(otp) {
  const regex = /^\d{6}$/;
  return regex.test(otp);
}

export function validPassword(password) {
  const regex =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,255}$/;
  return regex.test(password);
}

export function validPin(pin) {
  const regex = /^\d{4}$/;
  return regex.test(pin);
}
