const express = require('express');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const router = express.Router();

// Accept Prisma client as parameter (even if not used)
module.exports = (prisma) => {
  // Initialize Google Generative AI
  const genAI = new GoogleGenerativeAI(process.env.VITE_GEMINI_API_KEY);

  // Chat with ELZR AI
  router.post('/chat', async (req, res) => {
    try {
      const { messages } = req.body;

      // Initialize the model
      const model = genAI.getGenerativeModel({ model: 'gemini-pro' });

      // Format the prompt for the AI
      const formattedMessages = messages.map(msg => `${msg.role}: ${msg.text}`).join('\n');
      const prompt = `You are ELZR, a secure AI assistant for the ELZR Hunt game. ${formattedMessages}\nAssistant:`;

      // Generate content
      const result = await model.generateContent(prompt);
      const response = await result.response;
      const text = response.text();

      res.json({ text });
    } catch (error) {
      console.error('Error with AI chat:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  return router;
};