const express = require('express');
const http = require('http');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const socketIo = require('socket.io');
const connection = require('./connection');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'Radhe@123';

const server = http.createServer(app);
const io = socketIo(server)
app.use(bodyParser.json());
app.use(cookieParser());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const users = []; // This is a temporary in-memory storage for users
const activeSessions = {}; // Store active sessions

const apires=[];
// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Home page
app.get('/', (req, res) => {
    res.render('index');
});



io.on('connection', (socket) => {
    console.log('a user connected');

    socket.on('disconnect', () => {
        console.log('user disconnected');
    });

    socket.on('chat message', (msg) => {
        console.log('message: ' + msg);
        io.emit('chat message', msg);
    });
});


// Register endpoint
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
   // const hashedPassword = await bcrypt.hash(password, 8);
    // users.push({ username, password: hashedPassword });

    const query = 'INSERT INTO users (username, password) VALUES (?, ?)';
    connection.query(query, [username, password], (err, result) => {

        if (err) { }
        else {
            res.json({ message: "insert sucessfully" })

        }
    })

});

// Login endpoint
app.post('/login', async (req, res) => {


    const query = 'select username,password from users';
    connection.query(query, (err, result) => {

        if (err) { }
        else {
    
            const { username, password } = req.body;
            const user = result.find(u => u.username == username);
            if (!user) {
                return res.status(400).send({ message: 'Invalid username ' });
            }

            const isPasswordValid = result.find(u => u.password == password);

            if (!isPasswordValid) {
                return res.status(400).send({ message: 'Invalid  password' });
            }
            if (activeSessions[user.id]) {
                // Invalidate existing session (logout previous session)
                delete activeSessions[user.id];
            }
            const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1h' });
            activeSessions[user.id] = token; // Store token in activeSessions

            res.cookie('token', token, { httpOnly: true, secure: true }); // Set the token in HTTP-only cookie
            res.send({ message: 'Login successful' });
        }
    })

   
});

// Middleware to authenticate the token
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).send({ message: 'No token provided' });
    }
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).send({ message: 'Failed to authenticate token' });
        }
        req.user = user;
        next();
    });
};

// Protected route
// app.get('/protected', authenticateToken, (req, res) => {
//     res.send({ message: 'This is a protected route', user: req.user });
// });
app.get('/websocket', authenticateToken, (req, res) => {
    res.render('websocket');
});

server.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
