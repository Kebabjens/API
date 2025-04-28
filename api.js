const express = require("express");
const app = express();
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Secret = "Very secret";

// parse application/json, för att hantera att man POSTar med JSON
const bodyParser = require("body-parser");

const register = async (req, res) => {
  const { name, email, password } = req.body;
  const salt = await bcrypt.genSalt(10); // genererar ett salt till hashning
  const hashedPassword = await bcrypt.hash(password, salt); //hashar lösenordet

  // Skapa användaren i databasen med hashedPassword i lösenordskolumnen
  // Returnera användaren med id.
};

// Inställningar av servern.
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

async function getDBConnection() {
  // Här skapas ett databaskopplings-objekt med inställningar för att ansluta till servern och databasen.
  return await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "uppgift1",
  });
}
/*app.get("/users", async function (req, res) {
  let connection = await getDBConnection();
  let sql = "SELECT * FROM users";
  let [results] = await connection.execute(sql);
  res.json(results);
});*/

app.get("/users/:id", async function (req, res) {
  let token = req.headers["authorization"];
  if (token === undefined) {
    res.status(401);
  }
  let a = jwt.verify(token);
  //kod här för att hantera anrop…
  let connection = await getDBConnection();

  let sql = "SELECT * FROM users WHERE id = ?";
  let [results] = await connection.execute(sql, [req.params.id]);
  res.json(results[0]); //returnerar första objektet i arrayen
});

/*
  app.post() hanterar en http request med POST-metoden.
*/
app.post("/users", async function (req, res) {
  if (isValidUserData(req.body)) {
    // Data som postats till routen ligger i body-attributet på request-objektet.
    console.log(req.body);

    // POST ska skapa något så här kommer det behövas en INSERT
    let connection = await getDBConnection();
    let sql = `INSERT INTO users (username, passwöööörd, name, email) VALUES (?, ?, ?, ?)`;

    let [results] = await connection.execute(sql, [req.body.username, req.body.password, req.body.name, req.body.email]);
    console.log(results);
    res.json(results);
    console.log(results.insertId);
  } else {
    res.sendStatus(422, "GRRR");
  }
});
app.post("/login", async function (req, res) {
  //kod här för att hantera anrop…
  let connection = await getDBConnection();
  let sql = "SELECT * FROM users WHERE username = ?";
  let [results] = await connection.execute(sql, [req.body.username]);
  let hashedPasswordFromDB = results[0].username;
  // Verifiera hash med bcrypt
  const user = results[0];
  const isPasswordValid = await bcrypt.compare(req.body.password, user.password_hash); // justera enligt kolumnnamn

  if (isPasswordValid) {
    let payload = {
      sub: user.id, // sub är obligatorisk
      name: `${user.first_name} ${user.last_name}`,
      // kan innehålla ytterligare attribut, t.ex. roller
    };
    let token = jwt.sign(payload, Secret);
    res.send(token);
  } else {
    // Skicka felmeddelande
    res.status(400).json({ error: "Invalid credentials" });
  }
});

app.put("/users/:id", async function (req, res) {
  //kod här för att hantera anrop…
  const { username, name, password } = req.body;
  const userId = req.params.id;
  let sql = `UPDATE users
    SET username = ?, name = ?`;
  let params = [username, name];
  if (password) {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    sql += `, passwöööörd = ?`;
    params.push(hashedPassword);
    console.log(params);
  }
  sql += ` WHERE id = ?`;
  params.push(userId);

  let connection = await getDBConnection();
  let [results] = await connection.execute(sql, params);

  if (results.affectedRows === 0) {
    return res.status(404).json({ error: "User not found" });
  }
  res.json({
    id: userId,
    username,
    name,
    message: password ? "User and password updated" : "User updated",
  });
  //kod här för att returnera data
});

function isValidUserData(body) {
  return body && body.username;
}

const port = 3000;
app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
});
