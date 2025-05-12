const express = require("express");
const app = express();
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Secret = "Very secret";

// parse application/json
const bodyParser = require("body-parser");

const register = async (req, res) => {
  const { name, email, password } = req.body;
  const salt = await bcrypt.genSalt(10); // generera ett salt
  const hashedPassword = await bcrypt.hash(password, salt); // hash lösenordet

  // Skapa användaren i databasen med hashedPassword
  let connection = await getDBConnection();
  let sql = "INSERT INTO users (name, email, password) VALUES (?, ?, ?)";
  let [results] = await connection.execute(sql, [name, email, hashedPassword]);
  res.json({ id: results.insertId, name, email });
};

// Skyddade rutter middleware (kontrollera JWT)
const authenticateJWT = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ error: "Token required" });

  jwt.verify(token, Secret, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
};

// Inställningar av servern
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Databasanslutning
async function getDBConnection() {
  return await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "uppgift1",
  });
}

// Inloggning och skapa JWT
app.post("/login", async (req, res) => {
  let connection = await getDBConnection();
  let sql = "SELECT * FROM users WHERE username = ?";
  let [results] = await connection.execute(sql, [req.body.username]);

  if (results.length === 0) return res.status(400).json({ error: "Invalid credentials" });

  const user = results[0];
  console.log("req.body.password:", req.body.password);
  console.log("user:", user);
  console.log("user.password_hash:", user.password);
  const isPasswordValid = await bcrypt.compare(req.body.password, user.password);

  if (isPasswordValid) {
    const payload = { sub: user.id, username: user.username };
    const token = jwt.sign(payload, Secret, { expiresIn: "1h" });
    res.json({ token });
  } else {
    res.status(400).json({ error: "Invalid credentials" });
  }
});

app.get("/users/", async (req, res) => {
  let connection = await getDBConnection();
  let sql = "SELECT  id, username, name, email FROM users";
  let [results] = await connection.execute(sql);

  res.json(results);
});
// Hämta användare med ID (skyddad)
app.get("/users/:id", authenticateJWT, async (req, res) => {
  let connection = await getDBConnection();
  let sql = "SELECT * FROM users WHERE id = ?";
  let [results] = await connection.execute(sql, [req.params.id]);

  if (results.length === 0) return res.status(404).json({ error: "User not found" });
  res.json(results[0]);
});

// Uppdatera användare (skyddad)
app.put("/users/:id", authenticateJWT, async (req, res) => {
  const { username, name, password } = req.body;
  const userId = req.params.id;

  let sql = "UPDATE users SET username = ?, name = ? WHERE id = ?";
  let params = [username, name];

  if (password) {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    sql = "UPDATE users SET username = ?, name = ?, password = ? WHERE id = ?";
    params.push(hashedPassword);
  }

  let connection = await getDBConnection();
  let [results] = await connection.execute(sql, params);

  if (results.affectedRows === 0) return res.status(404).json({ error: "User not found" });

  res.json({
    id: userId,
    username,
    name,
    message: password ? "User and password updated" : "User updated",
  });
});

// Skapa användare
app.post("/users", async (req, res) => {
  if (isValidUserData(req.body)) {
    const { username, name, email, password } = req.body;
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    let connection = await getDBConnection();
    let sql = "INSERT INTO users (username, name, email, password) VALUES (?, ?, ?, ?)";
    let [results] = await connection.execute(sql, [username, name, email, hashedPassword]);
    res.json({ id: results.insertId, username, name, email });
  } else {
    res.status(422).json({ error: "Invalid user data" });
  }
});

function isValidUserData(body) {
  return body && body.username && body.password;
}

// dokumentation
app.get("/", (req, res) => {
  res.send(`<h1> Dokumentation</h1>
    <h2>Routes<h2>
    <h3> GET /users <h3>
    <p> Returnerar alla användare <p>
    <h3> GET /users/(id) <h3>
    <p> Returnerar användaren med angivet id eller returnerar 204 om användaren saknas<p>
    <h3> POST /users <h3>
    <p> Skapar en ny användare med JSON på formatet: (username, name, email, password) <p>
    <h3> POST /login <h3>
    <p> Logga in med username och password<p>
    <h3> PUT /users/(id) <h3>
    <p> Ändra information om användaren med id (id) och kräver token <p>`);
});

const port = 3000;
app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
});
