require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");
const bodyParser = require("body-parser");
const router = express.Router();
const PORT = process.env.PORT || 3001;
const app = express();
const prisma = new PrismaClient();

app.use(express.json());

const verifyToken = (req, res, next) => {
  const authHeaders = req.headers["authorization"];
  if (!authHeaders) {
    return res.status(400).json("no auth headers present");
  }
  console.log(authHeaders);
  const token = authHeaders.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send({ message: "Unauthorized" });
    }
    console.log("token verified!", decoded);
    req.user = decoded;
    next();
  });
};

app.post("/api/users/register", async (req, res, next) => {
  const { email, firstName, lastName, password } = req.body;
  try {
    // Check if email is already in use
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ message: "Email already in use" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 5);

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
        expiresIn: "24H",
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
});

app.post("/api/users/login", async (req, res, next) => {
  const { email, password } = req.body;
  try {
    const user = await prisma.user.findMany({
      where: { email },
    });
    console.log(user);
    const passwordCheck = await bcrypt.compare(password, user[0].password);
    if (!passwordCheck) {
      return res.status(401);
    }
    const token = jwt.sign(
      {
        id: user[0].id,
        email: user[0].email,
        firstName: user[0].firstName,
        lastName: user[0].lastName,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "24H",
      }
    );
    res.status(201).json({ token, message: "login successful" });
  } catch (error) {}
});

app.post("/api/users/aboutMe", verifyToken, async (req, res, next) => {
  console.log(req.user);
  res.status(201).json({firstName: req.user.firstName, lastName: req.user.lastName, email: req.user.email})
});

module.exports = router;
// Start the server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
