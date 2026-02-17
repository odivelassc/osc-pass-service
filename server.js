// Updated server.js

const express = require('express');
const app = express();

// Middleware to handle JSON requests
app.use(express.json());

// Function to validate HTTPS URLs
function isValidHttpsUrl(url) {
    const pattern = /^https:\/\/[^\s$.?#].[^\s]*$/;
    return pattern.test(url);
}

// Sample endpoint to set logo and hero images
app.post('/update-images', (req, res) => {
    const { logoUrl, heroImageUrl } = req.body;

    if (!isValidHttpsUrl(logoUrl) || !isValidHttpsUrl(heroImageUrl)) {
        return res.status(400).json({ message: 'Invalid image URLs. They must be valid HTTPS URLs.' });
    }

    // Logic to save the URLs would go here
    res.status(200).json({ message: 'Images updated successfully.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});