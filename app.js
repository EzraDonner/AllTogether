const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");
const bodyParser = require("body-parser");
const router = express.Router();

const app = express();
const prisma = new PrismaClient();

const SECRET_KEY = "your_secret_key"; // Replace with a secure key

exports.registerUser = async (req, res) => {
  const { email, firstName, lastName, password } = req.body;

  try {
    // Check if email is already in use
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ message: "Email already in use" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save user to the database
    const newUser = await prisma.user.create({
      data: {
        email,
        firstName,
        lastName,
        password: hashedPassword,
      },
    });

    // Create a JSON Web Token (JWT)
    const token = jwt.sign(
      { id: newUser.id, email: newUser.email },
      process.env.JWT_SECRET,
      {
        expiresIn: process.env.JWT_EXPIRATION,
      }
    );

    // Return success response
    res.status(201).json({
      message: "User registered successfully",
      token,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
};

// Define the register endpoint
module.exports = router;

const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json()); // Parse JSON

// Start the server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
