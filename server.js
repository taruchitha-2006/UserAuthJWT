const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "my_super_secret_key";

app.use(express.json());

const db = new sqlite3.Database("./users.db");

// Create users table
db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
`, (err) => {
    if (err) {
        console.error("Database error:", err.message);
    } else {
        console.log("Users table ready");
    }
});


// REGISTER
app.post("/api/auth/register", async (req, res) => {

    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({
            error: "Username and password are required"
        });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        db.run(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            [username, hashedPassword],
            function (err) {

                if (err) {
                    if (err.message.includes("UNIQUE")) {
                        return res.status(409).json({
                            error: "Username already exists"
                        });
                    }

                    return res.status(500).json({
                        error: err.message
                    });
                }

                res.status(201).json({
                    message: "Registration successful",
                    userId: this.lastID
                });
            }
        );

    } catch (error) {
        res.status(500).json({
            error: "Server error"
        });
    }
});


// LOGIN
app.post("/api/auth/login", (req, res) => {

    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({
            error: "Username and password are required"
        });
    }

    db.get(
        "SELECT * FROM users WHERE username = ?",
        [username],
        async (err, user) => {

            if (err) {
                return res.status(500).json({
                    error: err.message
                });
            }

            if (!user) {
                return res.status(401).json({
                    error: "Invalid username or password"
                });
            }

            const passwordMatch = await bcrypt.compare(
                password,
                user.password
            );

            if (!passwordMatch) {
                return res.status(401).json({
                    error: "Invalid username or password"
                });
            }

            const token = jwt.sign(
                {
                    id: user.id,
                    username: user.username
                },
                JWT_SECRET,
                {
                    expiresIn: "1h"
                }
            );

            res.json({
                message: "Login successful",
                token: token
            });
        }
    );
});


// JWT MIDDLEWARE
function authenticateToken(req, res, next) {

    const authHeader = req.headers["authorization"];

    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({
            error: "Access token required"
        });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {

        if (err) {
            return res.status(403).json({
                error: "Invalid or expired token"
            });
        }

        req.user = user;
        next();
    });
}


// PROTECTED ROUTE
app.get("/api/profile", authenticateToken, (req, res) => {

    res.json({
        message: "You can access this protected route",
        user: req.user
    });

});


// START SERVER
app.listen(PORT, () => {
    console.log(`User Authentication server running on port ${PORT}`);
});