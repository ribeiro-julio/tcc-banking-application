const BASE_URL = "http://localhost:3000/api";

twoFaSessionValidation();

// test login validation
async function testLoginValidations() {
  const emails = [
    "user",
    "user@",
    "user@domain",
    "user@domain.",
    "user@domain.com",
    "a@b.c",
    "user@domain.com--",
    "user@domain.com'--",
    "user@domain.comuser@domain.comuser@domain.comuser@domain.comuser@domain.comuser@domain.comuser@domain.comuser@domain.comuser@domain.com",
    "user.1@email.com",
    "user.1@email.com",
  ];
  const password = "senhaforte";

  for (const email of emails) {
    const response = await request("login", null, { email, password }, "POST");
    console.log(`${email}:${password} - ${JSON.stringify(response)}`);
  }
}

// test 2fa sessions
async function twoFaSessionValidation() {
  const paths = ["otp/disable", "otp/generate"];

  let response = await request(
    "login",
    null,
    { email: "user.1@email.com", password: "senhaforte" },
    "POST"
  );
  let { token } = JSON.parse(response.data);

  for (const path of paths) {
    response = await request(path, token, null, "POST");
    console.log(`${path} - ${JSON.stringify(response)}`);
  }

  response = await request("otp/validate", token, { token: "397463" }, "POST");
  token = JSON.parse(response.data).token;

  for (const path of paths) {
    response = await request(path, token, null, "POST");
    console.log(`${path} - ${JSON.stringify(response)}`);
  }
}

async function request(path, auth, body, method) {
  let headers = {};
  auth !== null
    ? (headers = {
        "Content-Type": "application/json",
        Authorization: `Bearer ${auth}`,
      })
    : (headers = { "Content-Type": "application/json" });

  let reqBody = JSON.stringify({});
  body !== null
    ? (reqBody = JSON.stringify(body))
    : (reqBody = JSON.stringify({}));

  const request = await fetch(`${BASE_URL}/${path}`, {
    method: method,
    headers: headers,
    body: reqBody,
  });

  const data = await request.text();

  return { status: request.status, data };
}
