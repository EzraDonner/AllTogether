const express = require("express");
const dotenv = require("dotenv");

dotenv.config(); // Load environment variables from a .env file

const app = express();
const port = process.env.PORT || 5000;

// Middleware to handle JSON request bodies
app.use(express.json());

// Basic route
app.get("/", (req, res) => {
  res.send("Hello World!");
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
