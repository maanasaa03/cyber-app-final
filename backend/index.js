import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { GoogleGenerativeAI } from "@google/generative-ai";

// Load environment variables
dotenv.config();

// Initialize Express
const app = express();
app.use(express.json());
app.use(cors());

// Initialize Gemini API
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((error) => {
    console.error("❌ MongoDB Connection Error:", error);
    process.exit(1);
  });

// User Schema
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
});

const User = mongoose.model("User", userSchema);

// Middleware for JWT Authentication
const verifyToken = (req, res, next) => {
  let token = req.headers["authorization"];
  
  if (!token) return res.status(403).send("A token is required for authentication");

  if (token.startsWith("Bearer ")) {
    token = token.slice(7, token.length);
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).send("Invalid Token");
  }
};

// User Registration
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });

    await newUser.save();
    res.json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ error: "Error registering user" });
  }
});

// User Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: user._id, email }, process.env.JWT_SECRET, { expiresIn: "24h" });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: "Error logging in" });
  }
});

//Chatbot API
app.post('/chatbot', async (req, res) => {
  const { message } = req.body;

  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }

  try {
    const response = await fetch(`https://generativelanguage.googleapis.com/v1/models/gemini-1.5-flash:generateContent?key=${process.env.GEMINI_API_KEY}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ parts: [{ text: message }] }]
      })
    });

    const data = await response.json();
    const reply = data.candidates?.[0]?.content?.parts?.[0]?.text || "No response from AI.";

    res.json({ reply });
  } catch (error) {
    console.error('Chatbot API Error:', error);
    res.status(500).json({ error: 'Failed to fetch response from chatbot' });
  }
});


// Website Analysis Endpoint
app.post('/analyze', async (req, res) => {
  const { url } = req.body;

  if (!url || !/^https?:\/\/.+\..+$/.test(url)) {
    return res.status(400).json({ error: 'Valid URL is required' });
  }

  try {
    // Fetch website content (without axios)
    const siteResponse = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
    const textContent = await siteResponse.text();

    // AI-based content analysis
    const aiResponse = await fetch(`https://generativelanguage.googleapis.com/v1/models/gemini-1.5-flash:generateContent?key=${process.env.GEMINI_API_KEY}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ parts: [{ text: `Analyze this website content for security risks: ${textContent.slice(0, 5000)}` }] }]
      })
    });

    const aiData = await aiResponse.json();
    const aiAnalysis = aiData.candidates?.[0]?.content?.parts?.[0]?.text || "No analysis available.";

    // Security Scoring Logic
    let securityScore = 100;

    if (!url.startsWith('https')) securityScore -= 30; // Penalize HTTP

    try {
      // VirusTotal API Call
      const vtResponse = await fetch(`https://www.virustotal.com/api/v3/urls/${encodeURIComponent(url)}`, {
        headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }
      });
      const vtData = await vtResponse.json();

      if (vtData?.data?.attributes?.last_analysis_stats?.malicious > 0) {
        securityScore -= 50;
      }
    } catch (err) {
      console.warn('VirusTotal API Error:', err.message);
    }

    try {
      // WHOIS API Call
      const whoisResponse = await fetch(`https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${process.env.WHOIS_API_KEY}&domainName=${url}`);
      const whoisData = await whoisResponse.json();
      
      const domainAge = whoisData.WhoisRecord?.createdDate;
      if (domainAge) {
        const ageInYears = (new Date() - new Date(domainAge)) / (1000 * 60 * 60 * 24 * 365);
        if (ageInYears < 1) securityScore -= 20; // Penalize new domains
      }
    } catch (err) {
      console.warn('WHOIS API Error:', err.message);
    }

    // AI-based risk detection
    const riskKeywords = ["scam", "phishing", "malware", "unsafe", "low credibility", "fake", "fraud", "suspicious"];
    if (riskKeywords.some(keyword => aiAnalysis.includes(keyword))) {
      securityScore -= 30;
    }

    securityScore = Math.max(securityScore, 0); // Prevent negative scores

    res.json({ securityScore, analysis: aiAnalysis });
  } catch (error) {
    console.error('Website Analysis Error:', error.message);
    res.status(500).json({ error: 'Failed to analyze website. The website may block automated requests.' });
  }
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));



