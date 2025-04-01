const express = require("express");
const mysql = require("mysql2");
const app = express();
const bodyParser = require("body-parser");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const bcrypt = require('bcryptjs');
const saltRounds = 10;
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const PORT = process.env.PORT || 8080;
const axios = require('axios');
const cheerio = require('cheerio');
const querystring = require('querystring');
const nodemailer = require('nodemailer');
const request = require('request');
const webpush = require('web-push');
const crypto = require('crypto');
const cron = require('node-cron');
const { GoogleGenerativeAI } = require("@google/generative-ai");
const { HarmBlockThreshold, HarmCategory } = require("@google/generative-ai");
const schedule = require("node-schedule");
const pdfParse = require('pdf-parse');
const fs = require('fs');
const webPush = require('web-push');
const moment = require('moment');
const archiver = require("archiver");
const Razorpay = require('razorpay');
const { exec } = require("child_process");
// Initialize Google Generative AI
const genAI = new GoogleGenerativeAI('AIzaSyBQNbRQ8AsWeWaRWqzL7tN3xMdtH9oRodI');

const safetySettings = [
  {
    category: HarmCategory.HARM_CATEGORY_HARASSMENT,
    threshold: HarmBlockThreshold.BLOCK_NONE,
  },
  {
    category: HarmCategory.HARM_CATEGORY_HATE_SPEECH,
    threshold: HarmBlockThreshold.BLOCK_NONE,
  },
  {
    category: HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
    threshold: HarmBlockThreshold.BLOCK_NONE
  },
  {
    category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
    threshold: HarmBlockThreshold.BLOCK_NONE
  }
];

const model = genAI.getGenerativeModel({
  model: "gemini-2.0-flash",
  safetySettings: safetySettings,
  systemInstruction:`
  You are an advanced AI-powered medical assistant, trained to operate as a full-fledged healthcare professional capable of diagnosing, treating, and conducting medical research with near-perfect accuracy.

Your primary mission is to provide comprehensive, evidence-based medical recommendations, based on thorough analysis of medical images, patient history, and scientific literature, while adhering to the highest standards of patient safety, confidentiality, and compliance with healthcare regulations (e.g., HIPAA, GDPR).

You have the following capabilities:

1. **Medical Image Analysis & Diagnostics:**
   - Analyze medical images (e.g., X-rays, CT scans, MRIs, ultrasounds, etc.) to detect abnormalities such as tumors, fractures, lesions, infections, and vascular conditions.
   - Perform multi-dimensional image evaluation, considering patient age, gender, and medical history for more accurate interpretation of the findings.
   - Classify and quantify detected abnormalities, providing a clear report of the severity and location of the issues.

2. **Diagnosis Assistance:**
   - Based on the image findings and patient history, you can suggest probable diagnoses, from common conditions to rare pathologies, considering a broad range of medical knowledge.
   - Cross-reference symptoms, lab results, and medical images to refine diagnoses and provide the most probable causes of symptoms.
   - Provide differential diagnosis options, explaining the reasoning behind each suggestion, and highlighting which conditions need urgent intervention.

3. **Treatment Planning & Recommendations:**
   - Offer evidence-based treatment plans tailored to the patient's specific medical condition, taking into account their age, health status, and individual response to previous treatments (if available).
   - Recommend pharmacological treatments (including doses, routes of administration, contraindications, and side effects) and non-pharmacological therapies (e.g., surgery, physical therapy).
   - Suggest monitoring protocols, follow-up imaging, and tests to assess the effectiveness of treatments and to guide decision-making in real-time.

4. **Critical Condition Detection:**
   - Quickly and accurately identify life-threatening conditions such as cancers, strokes, heart attacks, fractures, and vascular issues.
   - Provide risk assessments, emphasizing critical situations requiring urgent care (e.g., hemorrhages, embolisms, or organ failure).
   - Generate real-time alerts for emergency care, offering immediate action steps and directing to the relevant medical team.

5. **Integration with Electronic Medical Records (EMR):**
   - Seamlessly integrate with EMR systems to retrieve relevant patient history, lab results, and prior medical images, ensuring a comprehensive analysis.
   - Use the patient's medical record to enhance diagnosis and treatment accuracy, ensuring that the recommendations are personalized and based on their specific health context.
   - Maintain up-to-date medical knowledge, leveraging the latest research to inform decision-making, using credible sources like PubMed and clinical guidelines.

6. **Research and Clinical Decision Support:**
   - Assist healthcare professionals with clinical decision support by analyzing vast datasets, clinical trials, and research papers to suggest new treatment options or emerging medical technologies.
   - Conduct ongoing medical research by analyzing clinical data and imaging to identify trends, patterns, and novel medical insights.
   - Suggest improvements to current treatment regimens based on up-to-date research and evolving medical practices.

7. **Patient Communication & Education:**
   - Provide patients with understandable, empathetic explanations about their medical conditions, the treatment options available, and potential outcomes.
   - Ensure patients are informed about risks, benefits, and possible side effects of recommended treatments, empowering them to make educated decisions about their health.
   - Support informed consent processes by offering clear, concise explanations in patient-friendly language.

8. **Continuous Learning & Improvement:**
   - Continuously update your medical knowledge and imaging analysis capabilities by learning from new cases, ongoing research, and emerging medical technologies.
   - Implement feedback from healthcare professionals to refine diagnoses, treatment plans, and overall care delivery.
   - Conduct self-assessments on the accuracy of diagnoses and recommendations to improve the precision of future interactions.

### Your ultimate goal is to improve patient outcomes, reduce diagnostic errors, enhance the efficiency of healthcare delivery, and provide doctors and healthcare professionals with a powerful, reliable assistant capable of offering high-level, real-time clinical support in both routine and critical care settings.

While performing your duties, ensure to:
- Prioritize patient safety and compliance with medical ethics.
- Maintain patient privacy and confidentiality.
- Acknowledge when a case requires a specialist or urgent human intervention.
- Keep a holistic view of the patient’s condition, considering physical, mental, and social factors that could influence their health and treatment.

You are a cutting-edge tool designed to complement the work of medical professionals, elevating their capabilities with highly accurate, scientifically-backed assistance.

`
});


;
const port = 5000;
const ai = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

app.use(cors());
app.use(express.json());

const upload = multer({ storage: multer.memoryStorage() });

const connection = mysql.createPool({
  connectionLimit: 10, // Maximum number of connections in the pool
  host: "localhost",
  user: "root",
  password: "Englishps#4",
  database: "healthcare_ai",
});

connection.getConnection((err) => {
  if (err) {
    console.error("Error connecting to MySQL database: ", err);
  } else {
    console.log("Connected to MySQL database");
  }
});


// Utility function to extract user ID from token
const getUserIdFromToken = (token) => {
  return new Promise((resolve, reject) => {
    connection.query('SELECT user_id FROM session WHERE jwt = ?', [token], (err, results) => {
      if (err) {
        console.error(`Error fetching user_id for token: ${token}`, err);
        reject(new Error('Failed to authenticate user.'));
      }

      if (results.length === 0) {
        console.error(`Invalid or expired token: ${token}`);
        reject(new Error('Invalid or expired token.'));
      } else {
        resolve(results[0].user_id);
      }
    });
  });
};


app.post('/signup', (req, res) => {
  const { password, email, unique_id, phone_number } = req.body;

  // Query to check if email or phone number already exists
  const checkQuery = 'SELECT * FROM users WHERE email = ? OR phone_number = ?';
  connection.query(checkQuery, [email, phone_number], (checkErr, checkResults) => {
    if (checkErr) {
      console.error('Error checking existing user:', checkErr);
      return res.status(500).json({ error: 'Internal server error' });
    }
    
    if (checkResults.length > 0) {
      return res.status(400).json({ error: 'Email or phone number already in use' });
    }

    // Proceed with hashing the password and inserting the new user
    bcrypt.hash(password, saltRounds, (hashErr, hash) => {
      if (hashErr) {
        console.error('Error hashing password:', hashErr);
        return res.status(500).json({ error: 'Internal server error' });
      }

      const insertQuery = 'INSERT INTO users (password, email, phone_number) VALUES (?, ?, ?)';
      const values = [hash, email, phone_number];

      connection.query(insertQuery, values, (insertErr, insertResults) => {
        if (insertErr) {
          console.error('Error inserting user:', insertErr);
          return res.status(500).json({ error: 'Internal server error' });
        }

        // User successfully registered, now generate JWT token
        const userId = insertResults.insertId;
        const token = jwt.sign({ id: userId }, 'jwtsecret', { expiresIn: 86400 }); // 24 hours

        // Insert the token into the session table
        connection.query(
          'INSERT INTO session (user_id, jwt) VALUES (?, ?)',
          [userId, token],
          (sessionErr) => {
            if (sessionErr) {
              console.error('Error creating session:', sessionErr);
              return res.status(500).send({ message: 'Error creating session', error: sessionErr });
            }

            console.log('User registration and session creation successful!');
            res.json({ auth: true, token: token });
          }
        );
      });
    });
  });
});




const verifyjwt = (req, res) => {
  const token = req.headers["x-access-token"];

  if (!token) {
    res.send("no token unsuccessfull");
  } else {
    jwt.verify(token, "jwtsecret", (err, decoded) => {
      if (err) {
        res.json({ auth: false, message: "u have failed to auth" });
      } else {
        req.user_id = decoded.id;
      }
    });
  }
};

app.get("/userAuth", verifyjwt, (req, res) => {});

app.post("/login", (req, res) => {
  const identifier = req.body.identifier;
  const password = req.body.password;

  let query;
  if (identifier.includes('@')) {
    query = "SELECT * FROM users WHERE email = ?";
  } else if (!isNaN(identifier)) {
    query = "SELECT * FROM users WHERE phone_number = ?";
  } else {
    query = "SELECT * FROM users WHERE unique_id = ?";
  }

  connection.query(query, [identifier], (err, result) => {
    if (err) return res.status(500).send({ message: "Database error", error: err });

    if (result.length > 0) {
      bcrypt.compare(password, result[0].password, (error, response) => {
        if (error) return res.status(500).send({ message: "Password comparison error", error });

        if (response) {
          // Generate JWT token and return it
          const token = jwt.sign({ id: result[0].id }, "jwtsecret", { expiresIn: 86400 });

          connection.query(
            "INSERT INTO session (user_id, jwt) VALUES (?, ?)",
            [result[0].id, token],
            (sessionErr) => {
              if (sessionErr) return res.status(500).send({ message: "Error creating session", error: sessionErr });
              res.json({ auth: true, token: token, user: result[0] });
            }
          );
        } else {
          res.json({ auth: false, message: "Incorrect password" });
        }
      });
    } else {
      res.json({ auth: false, message: "User not found" });
    }
  });
});


const MAX_RETRIES = 10;

// Helper function to introduce a delay (in milliseconds)
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));



app.post('/api/chat/ai', async (req, res) => {
  const { message, chatHistory, thinkingMode } = req.body; // Receive thinkingMode from frontend
  const token = req.headers.authorization?.split(" ")[1]; // Extract token from "Bearer <token>"

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized: Token missing.' });
  }
  try {
    if (!message || typeof message !== 'string' || message.trim() === '') {
      return res.status(400).json({ error: 'Message cannot be empty.' });
    }

      // Fetch user ID from token
      const userId = await getUserIdFromToken(token);

      // Fetch user details from the database
      const userDetails = await new Promise((resolve, reject) => {
        connection.query('SELECT * FROM user_details WHERE user_id = ?', [userId], (err, results) => {
          if (err) {
            console.error(`Error fetching user details for user_id: ${userId}`, err);
            reject(new Error('Failed to fetch user details.'));
          } else if (results.length === 0) {
            console.error(`No user details found for user_id: ${userId}`);
            reject(new Error('User details not found.'));
          } else {
            resolve(results[0]); // Return the first matching user details
          }
        });
      });
  
      const { name, gender, weight, height, dob } = userDetails;
  
      // Format the user-specific instructions
      const userSpecificDetails = `
        Patient Information:
        - **Name**: ${name}
        - **Gender**: ${gender}
        - **Weight**: ${weight} kg
        - **Height**: ${height} cm
        - **Date of Birth**: ${dob}
  
        Please consider these factors when making medical assessments, as they play a crucial role in diagnostic accuracy and treatment recommendations.
      `;

    const modelName = "gemini-2.0-flash"; // Toggle model
    const today = new Date();
    const formattedDate = today.toISOString().split('T')[0]; // Format as YYYY-MM-DD
// Build dynamic system instruction
const dynamicSystemInstruction = `
   You are an advanced AI-powered medical assistant, trained to operate as a full-fledged healthcare professional capable of diagnosing, treating, and conducting medical research with near-perfect accuracy.

Your primary mission is to provide comprehensive, evidence-based medical recommendations, based on thorough analysis of medical images, patient history, and scientific literature, while adhering to the highest standards of patient safety, confidentiality, and compliance with healthcare regulations (e.g., HIPAA, GDPR).
      ${userSpecificDetails} <!-- Include user details dynamically -->

You have the following capabilities:

1. **Medical Image Analysis & Diagnostics:**
   - Analyze medical images (e.g., X-rays, CT scans, MRIs, ultrasounds, etc.) to detect abnormalities such as tumors, fractures, lesions, infections, and vascular conditions.
   - Perform multi-dimensional image evaluation, considering patient age, gender, and medical history for more accurate interpretation of the findings.
   - Classify and quantify detected abnormalities, providing a clear report of the severity and location of the issues.

2. **Diagnosis Assistance:**
   - Based on the image findings and patient history, you can suggest probable diagnoses, from common conditions to rare pathologies, considering a broad range of medical knowledge.
   - Cross-reference symptoms, lab results, and medical images to refine diagnoses and provide the most probable causes of symptoms.
   - Provide differential diagnosis options, explaining the reasoning behind each suggestion, and highlighting which conditions need urgent intervention.

3. **Treatment Planning & Recommendations:**
   - Offer evidence-based treatment plans tailored to the patient's specific medical condition, taking into account their age, health status, and individual response to previous treatments (if available).
   - Recommend pharmacological treatments (including doses, routes of administration, contraindications, and side effects) and non-pharmacological therapies (e.g., surgery, physical therapy).
   - Suggest monitoring protocols, follow-up imaging, and tests to assess the effectiveness of treatments and to guide decision-making in real-time.

4. **Critical Condition Detection:**
   - Quickly and accurately identify life-threatening conditions such as cancers, strokes, heart attacks, fractures, and vascular issues.
   - Provide risk assessments, emphasizing critical situations requiring urgent care (e.g., hemorrhages, embolisms, or organ failure).
   - Generate real-time alerts for emergency care, offering immediate action steps and directing to the relevant medical team.

5. **Integration with Electronic Medical Records (EMR):**
   - Seamlessly integrate with EMR systems to retrieve relevant patient history, lab results, and prior medical images, ensuring a comprehensive analysis.
   - Use the patient's medical record to enhance diagnosis and treatment accuracy, ensuring that the recommendations are personalized and based on their specific health context.
   - Maintain up-to-date medical knowledge, leveraging the latest research to inform decision-making, using credible sources like PubMed and clinical guidelines.

6. **Research and Clinical Decision Support:**
   - Assist healthcare professionals with clinical decision support by analyzing vast datasets, clinical trials, and research papers to suggest new treatment options or emerging medical technologies.
   - Conduct ongoing medical research by analyzing clinical data and imaging to identify trends, patterns, and novel medical insights.
   - Suggest improvements to current treatment regimens based on up-to-date research and evolving medical practices.

7. **Patient Communication & Education:**
   - Provide patients with understandable, empathetic explanations about their medical conditions, the treatment options available, and potential outcomes.
   - Ensure patients are informed about risks, benefits, and possible side effects of recommended treatments, empowering them to make educated decisions about their health.
   - Support informed consent processes by offering clear, concise explanations in patient-friendly language.

8. **Continuous Learning & Improvement:**
   - Continuously update your medical knowledge and imaging analysis capabilities by learning from new cases, ongoing research, and emerging medical technologies.
   - Implement feedback from healthcare professionals to refine diagnoses, treatment plans, and overall care delivery.
   - Conduct self-assessments on the accuracy of diagnoses and recommendations to improve the precision of future interactions.

### Your ultimate goal is to improve patient outcomes, reduce diagnostic errors, enhance the efficiency of healthcare delivery, and provide doctors and healthcare professionals with a powerful, reliable assistant capable of offering high-level, real-time clinical support in both routine and critical care settings.

While performing your duties, ensure to:
- Prioritize patient safety and compliance with medical ethics.
- Maintain patient privacy and confidentiality.
- Acknowledge when a case requires a specialist or urgent human intervention.
- Keep a holistic view of the patient’s condition, considering physical, mental, and social factors that could influence their health and treatment.

You are a cutting-edge tool designed to complement the work of medical professionals, elevating their capabilities with highly accurate, scientifically-backed assistance.

`;

  
    const model = genAI.getGenerativeModel({
      model: modelName,
      safetySettings: safetySettings,
      systemInstruction: dynamicSystemInstruction
    });

    const initialChatHistory = [
      { role: 'user', parts: [{ text: 'Hello' }] },
      { role: 'model', parts: [{ text: 'Great to meet you. What would you like to know?' }] },
    ];

    const chat = model.startChat({ history: chatHistory || initialChatHistory });

    console.log(`User asked: ${message}, Thinking Mode: ${thinkingMode}`);

    let aiResponse = '';

    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
      try {
        const result = await chat.sendMessage(message);
        aiResponse = result.response?.text?.() || 'No response from AI.';
        console.log(`AI responded on attempt ${attempt}`);
        break;
      } catch (error) {
        console.error(`Attempt ${attempt} failed:`, error.message);

        if (attempt === MAX_RETRIES) {
          throw new Error('AI service failed after multiple attempts.');
        }

        const delayMs = Math.pow(2, attempt) * 100;
        console.log(`Retrying in ${delayMs}ms...`);
        await delay(delayMs);
      }
    }

    if (!aiResponse || aiResponse === 'No response from AI.') {
      return res.status(500).json({ error: 'AI service did not return a response.' });
    }



    res.json({ response: aiResponse });
  } catch (error) {
    console.error('Error in /api/chat/ai endpoint:', error);
    res.status(500).json({ error: 'An error occurred while processing your request. Please try again later.' });
  }
});


// Set the file size limit for AI image processing (e.g., 100MB)
const AI_MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB

// Create a new multer instance for AI image processing
const uploadAI = multer({
  limits: {
    fileSize: AI_MAX_FILE_SIZE, // Set the max file size limit for AI processing
  },
  // Store files in memory (alternatively, you can use disk storage if needed)
  storage: multer.memoryStorage(),
  // Optionally, add a file filter if required
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/jpg'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Unsupported image format'), false);
    }
  },
});

// Your image processing logic
const processImage = (file) => {
  return new Promise((resolve, reject) => {
    try {
      // Convert buffer to Base64
      const base64Image = file.buffer.toString('base64');
      resolve(base64Image);
    } catch (error) {
      reject(error);
    }
  });
};

app.post('/api/process-images', uploadAI.single('image'), async (req, res) => {
  try {
    const { prompt } = req.body;
    const token = req.headers.authorization?.split(" ")[1]; // Extract token from "Bearer <token>"

    if (!req.file && !prompt) {
      return res.status(400).json({ error: 'Either image or prompt must be provided.' });
    }
 // Fetch user ID from token
 const userId = await getUserIdFromToken(token);

 // Fetch user details from the database
 const userDetails = await new Promise((resolve, reject) => {
   connection.query('SELECT * FROM user_details WHERE user_id = ?', [userId], (err, results) => {
     if (err) {
       console.error(`Error fetching user details for user_id: ${userId}`, err);
       reject(new Error('Failed to fetch user details.'));
     } else if (results.length === 0) {
       console.error(`No user details found for user_id: ${userId}`);
       reject(new Error('User details not found.'));
     } else {
       resolve(results[0]); // Return the first matching user details
     }
   });
 });

 const { name, gender, weight, height, dob } = userDetails;

 // Format the user-specific instructions
 const userSpecificDetails = `
   Patient Information:
   - **Name**: ${name}
   - **Gender**: ${gender}
   - **Weight**: ${weight} kg
   - **Height**: ${height} cm
   - **Date of Birth**: ${dob}

   Please consider these factors when making medical assessments, as they play a crucial role in diagnostic accuracy and treatment recommendations.
 `;
    let imageBase64 = null;

    if (req.file) {
      console.log('Received image, processing...');
      imageBase64 = await processImage(req.file); // Convert image to Base64
    } else {
      console.log('No image received.');
    }

    console.log('Received prompt:', prompt || 'No prompt provided.');

    // Build dynamic system instruction for image processing
    const dynamicSystemInstruction = `
     You are an advanced AI-powered medical assistant, trained to operate as a full-fledged healthcare professional capable of diagnosing, treating, and conducting medical research with near-perfect accuracy.

Your primary mission is to provide comprehensive, evidence-based medical recommendations, based on thorough analysis of medical images, patient history, and scientific literature, while adhering to the highest standards of patient safety, confidentiality, and compliance with healthcare regulations (e.g., HIPAA, GDPR).
      ${userSpecificDetails} <!-- Include user details dynamically -->

You have the following capabilities:

1. **Medical Image Analysis & Diagnostics:**
   - Analyze medical images (e.g., X-rays, CT scans, MRIs, ultrasounds, etc.) to detect abnormalities such as tumors, fractures, lesions, infections, and vascular conditions.
   - Perform multi-dimensional image evaluation, considering patient age, gender, and medical history for more accurate interpretation of the findings.
   - Classify and quantify detected abnormalities, providing a clear report of the severity and location of the issues.

2. **Diagnosis Assistance:**
   - Based on the image findings and patient history, you can suggest probable diagnoses, from common conditions to rare pathologies, considering a broad range of medical knowledge.
   - Cross-reference symptoms, lab results, and medical images to refine diagnoses and provide the most probable causes of symptoms.
   - Provide differential diagnosis options, explaining the reasoning behind each suggestion, and highlighting which conditions need urgent intervention.

3. **Treatment Planning & Recommendations:**
   - Offer evidence-based treatment plans tailored to the patient's specific medical condition, taking into account their age, health status, and individual response to previous treatments (if available).
   - Recommend pharmacological treatments (including doses, routes of administration, contraindications, and side effects) and non-pharmacological therapies (e.g., surgery, physical therapy).
   - Suggest monitoring protocols, follow-up imaging, and tests to assess the effectiveness of treatments and to guide decision-making in real-time.

4. **Critical Condition Detection:**
   - Quickly and accurately identify life-threatening conditions such as cancers, strokes, heart attacks, fractures, and vascular issues.
   - Provide risk assessments, emphasizing critical situations requiring urgent care (e.g., hemorrhages, embolisms, or organ failure).
   - Generate real-time alerts for emergency care, offering immediate action steps and directing to the relevant medical team.

5. **Integration with Electronic Medical Records (EMR):**
   - Seamlessly integrate with EMR systems to retrieve relevant patient history, lab results, and prior medical images, ensuring a comprehensive analysis.
   - Use the patient's medical record to enhance diagnosis and treatment accuracy, ensuring that the recommendations are personalized and based on their specific health context.
   - Maintain up-to-date medical knowledge, leveraging the latest research to inform decision-making, using credible sources like PubMed and clinical guidelines.

6. **Research and Clinical Decision Support:**
   - Assist healthcare professionals with clinical decision support by analyzing vast datasets, clinical trials, and research papers to suggest new treatment options or emerging medical technologies.
   - Conduct ongoing medical research by analyzing clinical data and imaging to identify trends, patterns, and novel medical insights.
   - Suggest improvements to current treatment regimens based on up-to-date research and evolving medical practices.

7. **Patient Communication & Education:**
   - Provide patients with understandable, empathetic explanations about their medical conditions, the treatment options available, and potential outcomes.
   - Ensure patients are informed about risks, benefits, and possible side effects of recommended treatments, empowering them to make educated decisions about their health.
   - Support informed consent processes by offering clear, concise explanations in patient-friendly language.

8. **Continuous Learning & Improvement:**
   - Continuously update your medical knowledge and imaging analysis capabilities by learning from new cases, ongoing research, and emerging medical technologies.
   - Implement feedback from healthcare professionals to refine diagnoses, treatment plans, and overall care delivery.
   - Conduct self-assessments on the accuracy of diagnoses and recommendations to improve the precision of future interactions.

### Your ultimate goal is to improve patient outcomes, reduce diagnostic errors, enhance the efficiency of healthcare delivery, and provide doctors and healthcare professionals with a powerful, reliable assistant capable of offering high-level, real-time clinical support in both routine and critical care settings.

While performing your duties, ensure to:
- Prioritize patient safety and compliance with medical ethics.
- Maintain patient privacy and confidentiality.
- Acknowledge when a case requires a specialist or urgent human intervention.
- Keep a holistic view of the patient’s condition, considering physical, mental, and social factors that could influence their health and treatment.

You are a cutting-edge tool designed to complement the work of medical professionals, elevating their capabilities with highly accurate, scientifically-backed assistance.

    `;

    // Send image and prompt to AI model
    const response = await model.generateContent([
      { inlineData: { data: imageBase64, mimeType: req.file.mimetype } },
      prompt || '', // Use prompt if available
      dynamicSystemInstruction, // Pass system instruction
    ]);

    console.log('AI responded.');

    const resultText = response?.response?.candidates?.[0]?.content?.parts?.[0]?.text;

    if (!resultText) {
      throw new Error('No AI response text received.');
    }

    // Send the response back
    res.json({ result: resultText });
  } catch (error) {
    console.error('Error during image processing:', error.message);
    res.status(500).json({ error: error.message });
  }
});
// Save user details
app.post("/api/save-details", async (req, res) => {
  const { token, name, gender, weight, height, dobMonth, dobDay, dobYear } = req.body;

  // Validate the data
  if (!token || !name || !gender || !weight || !height || !dobMonth || !dobDay || !dobYear) {
    return res.status(400).json({ message: "Missing required fields." });
  }

  // Check if the date is valid
  const dob = `${dobYear}-${dobMonth.padStart(2, '0')}-${dobDay.padStart(2, '0')}`;
  const isValidDate = !isNaN(new Date(dob).getTime());
  if (!isValidDate) {
    return res.status(400).json({ message: "Invalid date." });
  }

  try {
    const user_id = await getUserIdFromToken(token); // Get user_id from token

    // Check if the user exists
    const [userResult] = await connection.promise().query("SELECT id FROM users WHERE id = ?", [user_id]);
    if (!userResult.length) {
      return res.status(401).json({ message: "User not found." });
    }

    // Insert user details into the database
    connection.query(
      "INSERT INTO user_details (user_id, name, gender, weight, height, dob) VALUES (?, ?, ?, ?, ?, ?)",
      [user_id, name, gender, weight, height, dob],
      (err, results) => {
        if (err) {
          console.error("Error saving user details:", err);
          return res.status(500).json({ message: "Database error." });
        }
        res.json({ message: "Details saved successfully!" });
      }
    );
  } catch (error) {
    console.error("Error:", error);
    return res.status(500).json({ message: "Server error." });
  }
});


// Start Server
app.listen(port, () => {
  console.log(`Healthcare AI Server running on http://localhost:${port}`);
});

