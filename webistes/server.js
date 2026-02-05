const express = require('express');
const path = require('path');
const app = express();
const port = 3000; // Using 3000 for local development

// Serve static files from the current directory
app.use(express.static(__dirname));

// Serve index.html for the root route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(port, () => {
    console.log(`Website running at http://localhost:${port}`);
    console.log(`If hosted on VPS, access it via your VPS IP address.`);
});
