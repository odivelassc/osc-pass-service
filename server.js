// server.js

const express = require('express');
const https = require('https');
const fs = require('fs');

const app = express();

// Middleware for serving static files
app.use(express.static('public'));

// SSL certificate options
const options = {
    cert: fs.readFileSync('path/to/fullchain.pem'),
    key: fs.readFileSync('path/to/privkey.pem')
};

// Route for serving the logo and hero images with HTTPS validation
app.get('/logo', (req, res) => {
    res.sendFile(__dirname + '/public/logo.png');
});

app.get('/hero', (req, res) => {
    res.sendFile(__dirname + '/public/hero.png');
});

// Start the server
const PORT = process.env.PORT || 3000;
https.createServer(options, app).listen(PORT, () => {
    console.log(`Server is running on https://localhost:${PORT}`);
});
