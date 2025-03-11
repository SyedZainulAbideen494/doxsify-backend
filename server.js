const express = require('express');
const app = express();
const port = 3000; // Choose any port you prefer, e.g., 3000

// Define a route handler for the root URL
app.get('/', (req, res) => {
  res.send('Hello, world! This is your Node.js server.');
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
