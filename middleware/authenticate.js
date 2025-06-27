const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");

// Укажи свой Cognito User Pool ID и регион
const REGION = "eu-north-1";
const USER_POOL_ID = "eu-north-1_vcXKxrYk5";
const ISSUER = `https://cognito-idp.${REGION}.amazonaws.com/${USER_POOL_ID}`;

const client = jwksClient({
  jwksUri: `${ISSUER}/.well-known/jwks.json`
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Missing or invalid token" });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, getKey, { issuer: ISSUER }, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token", error: err.message });
    }

    req.user = decoded;
    next();
  });
}

module.exports = authenticate;
