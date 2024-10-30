const express = require('express');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const app = express();
const port = process.env.PORT || 3000;
app.use(express.json());
app.use(cors());

const dbPath = path.join(__dirname, 'userdetails.db');
const secretKey = 'registerkey'; 
let db = null;

const initializeDBAndServer = async () => {
    try {
        db = await open({
            filename: dbPath,
            driver: sqlite3.Database,
        });
        app.listen(port, () => {
            console.log(`server is listening on port ${port}`);
        });
    } catch (error) {
        console.log(`DB Error: ${error.message}`);
    }
};

initializeDBAndServer();

app.post('/api/register', async (req, res) => {
    try {
        const { username, password, email } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        console.log(username,password,email);
        const insertDBQuery = `INSERT INTO userDetails (username, email, password) VALUES (?, ?, ?);`;
        await db.run(insertDBQuery, [username, email, hashedPassword]);

        const jwtToken = jwt.sign(
            { username, email },
            secretKey,
        );
        res.status(201).send({ jwtToken, message: 'User Registered Successfully' });
    } catch (error) {
        res.status(500).send("Error Registering User");
    }
});


app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        console.log(username,password);
        const getDBQuery = `SELECT * FROM userDetails WHERE username = ?;`;
        const user = await db.get(getDBQuery, [username]);

        if (!user) {
            return res.status(400).send("Invalid username or password");
        }

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(400).send("Invalid username or password");
        }

        const jwtToken = jwt.sign(
            { username: user.username, email: user.email },
            secretKey,
        );
        res.status(200).send({ jwtToken, message: 'Login Successful' });
    } catch (error) {
        res.status(500).send("Error Logging In User");
    }
});
