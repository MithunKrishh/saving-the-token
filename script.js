const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const JWT_SECRET = "my_jwt_secret_key"; 
const ENCRYPTION_KEY = crypto
  .createHash("sha256")
  .update(String("my_super_secret_key")) 
  .digest("base64")
  .substr(0, 32); 

const IV_LENGTH = 16; 

// Encrypt the JWT-signed payload
const encrypt = (payload) => {
  
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
  const iv = crypto.randomBytes(IV_LENGTH);

  // 3. Encrypt the JWT token
  const cipher = crypto.createCipheriv("aes-256-cbc", Buffer.from(ENCRYPTION_KEY), iv);
  let encrypted = cipher.update(token, "utf8", "hex");
  encrypted += cipher.final("hex");

  return iv.toString("hex") + ":" + encrypted;
};

// Decrypt and verify the JWT
const decrypt = (token) => {
  const [ivHex, encryptedToken] = token.split(":");
  const iv = Buffer.from(ivHex, "hex");

  const decipher = crypto.createDecipheriv("aes-256-cbc", Buffer.from(ENCRYPTION_KEY), iv);
  let decrypted = decipher.update(encryptedToken, "hex", "utf8");
  decrypted += decipher.final("utf8");

  const payload = jwt.verify(decrypted, JWT_SECRET);
  return payload;
};

module.exports = {
  encrypt,
  decrypt,
};
