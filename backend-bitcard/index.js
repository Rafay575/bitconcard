const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2/promise");
const bodyParser = require('body-parser');
const request = require('request');
const crypto = require('crypto');
const AES256 = require('aes-everywhere');
const axios = require("axios");

const app = express();

app.use(express.json());
app.use(cors());
app.use(bodyParser.json());
const pool = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "",
  database: "bitcard",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});
const AUTH_TOKEN =
  "Bearer at_test_1ebff3fe450c076ccf7c7e4b4a6082929f69369ebdc88b043e1d9a38524825d39018a5b0b4cf14c9562d6b0c11505086ccc55266595d5fddd4ce6bd36b1cb4e24f420d79169af859cf22b9331177f0a8ca559d017e40a63b77f06ee5e7360f90c07d81df878b919fb7bd6d74a47a664c37bf2cbc0690031d6caaf0ab1802a566ef0af3d04d85f9feb356c91f0614ee8740212285170434fa94968e24221b57ec7ee777ff1a7bc629e0a1069c7997c6d30e8bc58903ca853f3e548844ff99d0abefb836846f8dd5115fccfffceb1571901d3e7a60f40a02f54d248a66d956dec05836a9b7f341970388343a0dc76b441aec6e7de2813661e3cb6a6aa38820524b";
const API_URL = "https://issuecards.api.bridgecard.co/v1/issuing/sandbox";

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";
const Merchant_ID = '6a6ce54f-328f-4394-8e61-0fc760cb6702'
const Payment_API_key = 'pjjjSRxflEQZ5iBRf4wQBeYSbHGjYnk3UMkTbAIkbTxHNfsQ4q0dtMcri3VG1G8g4deNsgHLO9vpL0dyo64L4jAvfQcw6LQHlsQTtLnclgwzX7XYokiTzOcvEXufOvr1'

app.post("/api/checkout",async(req,res)=>{
  const {amount,curr} = req.body;
  
  const data = {
    "amount": amount,
    "currency": curr,
    "order_id": crypto.randomBytes(12).toString("hex"),
  }
  const sign = crypto.createHash("md5").update(Buffer.from(JSON.stringify(data)).toString("base64") + Payment_API_key).digest("hex")
  const response = await  axios.post("https://api.cryptomus.com/v1/payment",data,
  {  headers :{
      merchant: Merchant_ID,
      sign: sign
    }}
  );
  res.send(response.data)
})

const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "No token provided." });
  const token = authHeader.split(" ")[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Invalid token." });
    req.user = decoded;
    next();
  });
};

// Signup endpoint
app.post("/api/signup", async (req, res) => {
  const {
    firstName,
    lastName,
    email,
    password,
    confirmPassword,
    restrictedCheck,
  } = req.body;

  // Basic validation
  if (!firstName || !lastName || !email || !password || !confirmPassword) {
    return res.status(400).json({ error: "Missing required fields." });
  }
  if (password !== confirmPassword) {
    return res.status(400).json({ error: "Passwords do not match." });
  }
  if (!restrictedCheck) {
    return res
      .status(400)
      .json({
        error: "Please confirm you are not located in a restricted country.",
      });
  }

  try {
    // Check if user exists
    const [rows] = await pool.execute("SELECT * FROM users WHERE email = ?", [
      email,
    ]);
    if (rows.length > 0) {
      return res.status(400).json({ error: "User already exists." });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user record
    // restrictedCheck ? 1 : 0 converts `true` or any truthy value into `1`, otherwise `0`
    await pool.execute(
      `INSERT INTO users (firstName, lastName, email, password, restrictedCheck, role) 
       VALUES (?, ?, ?, ?, ?, ?)`,
      [firstName, lastName, email, hashedPassword, restrictedCheck ? 1 : 0, 0] // role always 0 for users
    );

    return res.status(201).json({ message: "User created successfully." });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Internal server error." });
  }
});
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Missing email or password." });
  }

  try {
    // Retrieve user by email
    const [rows] = await pool.execute("SELECT * FROM users WHERE email = ?", [
      email,
    ]);
    if (rows.length === 0) {
      return res.status(400).json({ error: "User not found." });
    }
    const user = rows[0];

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid credentials." });
    }

    // Generate a JWT token (expires in 1 hour)
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    // Capture IP address and user agent
    const ipHeader = req.headers["x-forwarded-for"]; // If behind a proxy
    const socketIp = req.socket?.remoteAddress; // Modern approach
    const expressIp = req.ip; // Express-based approach

    console.log("Debug IP Info:", { ipHeader, socketIp, expressIp });

    // Pick whichever is non-empty
    let ip = ipHeader || socketIp || expressIp || "";

    if (ip.startsWith("::ffff:")) {
      ip = ip.substring(7);
    }

    const userAgent = req.headers["user-agent"] || "";

    await pool.execute(
      "INSERT INTO login_history (user_id, ip_address, user_agent) VALUES (?, ?, ?)",
      [user.id, ip, userAgent]
    );

    const { password: pwd, ...userData } = user;
    return res.json({ message: "Login successful.", token, user: user });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Internal server error." });
  }
});
app.get("/api/users", async (req, res) => {
  try {
    const [rows] = await pool.execute(`
        SELECT 
          u.id,
          u.firstName,
          u.lastName,
          u.email,
          u.role,
          u.status,
          u.balance,
          (
            SELECT MAX(login_time) 
            FROM login_history 
            WHERE login_history.user_id = u.id
          ) AS lastLogin
        FROM users u
      `);

    const mappedUsers = rows.map((row) => {
      const name = `${row.firstName} ${row.lastName}`;

      const lastLoginStr = row.lastLogin
        ? new Date(row.lastLogin).toISOString().split("T")[0]
        : "Never";

      return {
        name,
        email: row.email,
        status: row.status || "Active",
        balance: row.balance || 0,
        lastLogin: lastLoginStr,
      };
    });

    return res.json(mappedUsers);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Internal server error." });
  }
});

app.get("/api/profile", verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      "SELECT id, firstName, lastName, email, role FROM users WHERE id = ?",
      [req.user.id]
    );
    if (rows.length === 0)
      return res.status(404).json({ error: "User not found." });
    return res.json({ user: rows[0] });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Internal server error." });
  }
});

app.get("/api/verify", verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.execute("SELECT * FROM users WHERE id = ?", [
      req.user.id,
    ]);
    if (rows.length === 0)
      return res.status(404).json({ error: "User not found." });
    const user = rows[0];
    return res.json({ valid: true, user });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Internal server error." });
  }
});

app.get("/api/login-history", verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      "SELECT * FROM login_history WHERE user_id = ? ORDER BY login_time DESC",
      [req.user.id]
    );
    return res.json({ history: rows });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Internal server error." });
  }
});

app.post("/register-cardholder", async (req, res) => {
  try {
    const response = await fetch(`${API_URL}/cardholder/register_cardholder`, {
      method: "POST",
      headers: {
        token: AUTH_TOKEN,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(req.body),
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.message || "API request failed");

    res.json(data);
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/create-card", (req, res) => {
  // Extract the PIN from the request body. If the field is empty, it will be defaulted by the API.
  const pin = req.body.pin || "1234";
  let encryptedPin = "";

  // Encrypt the PIN if it is provided
  if (pin) {
    if (pin.length !== 4) {
      return res.status(400).json({ error: "Pin must be exactly 4 digits." });
    }
    // Replace 'Bridgecard Secret Key' with your actual secret key from your dashboard.
    encryptedPin = AES256.encrypt(pin, "Bridgecard Secret Key");
    console.log("Encrypted PIN:", encryptedPin);
  }

  // Build the payload for the create card API request
  const payload = {
    cardholder_id:  "cd01bfe881af4860b70c799b7da4a8a6",
    card_type:  "virtual",
    card_brand: "Mastercard",
    card_currency:  "USD",
    card_limit: "500000", // or "1000000"
    transaction_reference:  "",
    funding_amount: req.body.funding_amount || "10",
    // Use the encrypted PIN if provided; if empty, the API will use its default mechanism.
    pin: encryptedPin,
   
  };

  const options = {
    method: "POST",
    url: `${API_URL}/cards/create_card`,
    headers: {
      token: AUTH_TOKEN,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  };

  // Call the API using the request library
  request(options, (error, response, body) => {
    if (error) {
      console.error("Request error:", error);
      return res.status(500).json({ error: error.message });
    }
    try {
      const data = JSON.parse(body);
      if (response.statusCode < 200 || response.statusCode >= 300) {
        throw new Error(data.message || "API request failed");
      }
      res.json(data);
    } catch (parseError) {
      console.error("Response parsing error:", parseError);
      res.status(500).json({ error: "Error parsing API response" });
    }
  });
});

const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
