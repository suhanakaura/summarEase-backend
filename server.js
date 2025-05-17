const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const natural = require("natural");
const winston = require("winston");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const cheerio = require('cheerio');
const fileUpload = require('express-fileupload');
const pdf = require('pdf-parse');
const mammoth = require('mammoth');
const translateText = require('translate-google');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(fileUpload({
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB max file size
    useTempFiles: true,
    tempFileDir: './tmp/',
    debug: true,
    createParentPath: true,
    parseNested: true,
    abortOnLimit: true
}));

// Create temp directory if it doesn't exist
const fs = require('fs');
const path = require('path');
const tempDir = path.join(__dirname, 'tmp');
if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir, { recursive: true });
}

// Logging setup
const logger = winston.createLogger({
    level: 'debug',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message }) => `${timestamp} - ${level}: ${message}`)
    ),
    transports: [
        new winston.transports.File({ filename: 'server.log' }),
        new winston.transports.Console()
    ]
});

// Language utilities
const supportedLanguages = {
    'en': 'English',
    'es': 'Spanish',
    'fr': 'French',
    'de': 'German',
    'it': 'Italian',
    'pt': 'Portuguese',
    'nl': 'Dutch',
    'ru': 'Russian',
    'ja': 'Japanese',
    'ko': 'Korean',
    'zh-CN': 'Chinese (Simplified)',
    'ar': 'Arabic',
    'hi': 'Hindi'
};

// Language detection and translation helper
const processLanguage = async (text, targetLang = 'en') => {
    try {
        // If text is already in English and target is English, return as is
        if (targetLang === 'en') {
            return {
                text: text,
                translated: false
            };
        }

        // Translate the text using translate-google
        const translation = await translateText(text, { 
            to: targetLang,
            from: 'auto' // Auto-detect source language
        });

        logger.debug(`Translated text to ${targetLang}`);
        
        return {
            text: translation,
            translated: true
        };
    } catch (error) {
        logger.error(`Translation error: ${error.message}`);
        throw new Error(`Translation failed: ${error.message}`);
    }
};

// MongoDB connection with retry mechanism
const MONGODB_URI = "mongodb://localhost:27017/summarease";

mongoose.set('strictQuery', false);

const connectWithRetry = async () => {
    let retries = 5;
    let delay = 1000;
    while (retries) {
        try {
            logger.debug(`Attempting to connect to MongoDB at ${MONGODB_URI}`);
            await mongoose.connect(MONGODB_URI, {
                serverSelectionTimeoutMS: 5000,
                family: 4
            });
            logger.info("MongoDB connected successfully");
            logger.info("MongoDB Status: Connected");
            return;
        } catch (err) {
            logger.error("MongoDB connection error: %s", err);
            retries -= 1;
            if (retries === 0) {
                logger.error("MongoDB connection failed after retries");
                process.exit(1);
            }
            await new Promise(resolve => setTimeout(resolve, delay));
            delay *= 2;
        }
    }
};

// Handle MongoDB connection events
mongoose.connection.on('connected', () => {
    logger.info('Mongoose connected to MongoDB');
});

mongoose.connection.on('error', (err) => {
    logger.error('Mongoose connection error:', err);
});

mongoose.connection.on('disconnected', () => {
    logger.warn('Mongoose disconnected');
});

// Graceful shutdown
process.on('SIGINT', async () => {
    try {
        await mongoose.connection.close();
        logger.info('Mongoose connection closed through app termination');
        process.exit(0);
    } catch (err) {
        logger.error('Error closing Mongoose connection:', err);
        process.exit(1);
    }
});

connectWithRetry();

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});
const User = mongoose.model("User", userSchema);

// Summary Schema
const summarySchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    originalText: { type: String, required: true },
    summarizedText: { type: String, required: true },
    wordCount: { type: Number, required: true },
    focus: { type: String },
    style: { type: String },
    format: { type: String, required: true, enum: ['paragraph', 'bullet_points'] },
    language: { type: String, required: true },
    title: { type: String, required: true },
    sourceType: { type: String, required: true, enum: ['text', 'url', 'file'] },
    createdAt: { type: Date, default: Date.now },
    metadata: {
        reading_time_seconds: Number,
        original_length: Number,
        summary_length: Number,
        was_translated: Boolean,
        key_terms: Array
    }
});
const Summary = mongoose.model("Summary", summarySchema);

// JWT Verification Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Expecting "Bearer <token>"
    
    if (!token) {
        logger.warn("No token provided in request");
        return res.status(401).json({ message: "Authentication token required" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key'); // Fallback secret for development
        req.user = decoded;
        logger.debug(`Token verified successfully for user: ${decoded.id}`);
        next();
    } catch (error) {
        logger.error(`Token verification failed: ${error.message}`);
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ message: "Token has expired" });
        }
        return res.status(403).json({ message: "Invalid token" });
    }
};

// Authentication Routes
app.post("/api/auth/register", async (req, res) => {
    const { username, email, password } = req.body;
    logger.info("Register request: username=%s, email=%s", username, email);
    try {
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            logger.warn("User already exists: email=%s or username=%s", email, username);
            return res.status(400).json({ message: "Username or email already exists" });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, email, password: hashedPassword });
        await user.save();
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
        logger.info("User registered and token issued: username=%s", username);
        res.status(201).json({ message: "User registered successfully", token });
    } catch (error) {
        logger.error("Error registering user: %s", error.message);
        res.status(500).json({ message: "Error registering user", details: error.message });
    }
});

app.post("/api/auth/login", async (req, res) => {
    const { email, password } = req.body;
    logger.info("Login request: email=%s", email);
    try {
        const user = await User.findOne({ email });
        if (!user) {
            logger.warn("User not found: email=%s", email);
            return res.status(400).json({ message: "User not found" });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            logger.warn("Invalid credentials for email=%s", email);
            return res.status(400).json({ message: "Invalid credentials" });
        }
        const token = jwt.sign({ id: user._id.toString() }, process.env.JWT_SECRET, { expiresIn: "1h" });
        logger.info("Login successful, token issued for userId=%s", user._id);
        res.json({ token });
    } catch (error) {
        logger.error("Error logging in: %s", error.message);
        res.status(500).json({ message: "Error logging in", details: error.message });
    }
});

// File processing utilities
const processFile = async (file) => {
    if (!file) {
        throw new Error('No file provided');
    }

    logger.debug(`Processing file: name=${file.name}, type=${file.mimetype}, size=${file.size} bytes`);

    // Check if file has data
    if (!file.data && !file.tempFilePath) {
        throw new Error('File is empty or contains no data');
    }

    const fileType = file.mimetype;
    let extractedText = '';

    try {
        switch (fileType) {
            case 'application/pdf':
                logger.debug('Processing PDF file...');
                if (file.tempFilePath) {
                    const fileBuffer = fs.readFileSync(file.tempFilePath);
                    const pdfData = await pdf(fileBuffer);
                    if (!pdfData || !pdfData.text) {
                        throw new Error('Could not extract text from PDF');
                    }
                    extractedText = pdfData.text;
                } else {
                    throw new Error('No temporary file available for PDF processing');
                }
                break;

            case 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
            case 'application/msword':
                logger.debug('Processing Word document...');
                const result = await mammoth.extractRawText({ buffer: file.data });
                if (!result || !result.value) {
                    throw new Error('Could not extract text from Word document');
                }
                extractedText = result.value;
                break;

            case 'text/plain':
                logger.debug('Processing text file...');
                if (file.tempFilePath) {
                    extractedText = fs.readFileSync(file.tempFilePath, 'utf8');
                } else if (file.data) {
                    extractedText = file.data.toString('utf8');
                } else {
                    throw new Error('No data available in text file');
                }
                break;

            default:
                throw new Error(`Unsupported file type: ${fileType}`);
        }

        // Clean up the extracted text
        extractedText = extractedText
            .replace(/\r\n/g, '\n')
            .replace(/\n{3,}/g, '\n\n')
            .trim();

        if (!extractedText) {
            throw new Error('No text could be extracted from the file');
        }

        logger.debug(`Successfully extracted ${extractedText.length} characters from ${fileType} file`);
        return extractedText;
    } catch (error) {
        logger.error(`File processing error: ${error.message}`);
        throw new Error(`Failed to process file: ${error.message}`);
    }
};

// Improved summarization function
const summarizeText = (text, targetWords = 130, focus = null, format = 'paragraph') => {
    logger.debug(`Starting summarization: textLength=${text.length}, targetWords=${targetWords}, focus=${focus}, format=${format}`);
    
    // Clean and normalize text
    text = text.replace(/[^\w\s.,!?]/g, " ").replace(/\s+/g, " ").trim();
    
    // Tokenize sentences
    const tokenizer = new natural.SentenceTokenizer();
    const sentences = tokenizer.tokenize(text);
    
    if (sentences.length < 2) {
        logger.debug("Text too short, returning as is");
        return { summary: text, word_count: text.split(/\s+/).length };
    }
    
    // Initialize TF-IDF
    const tfidf = new natural.TfIdf();
    
    // Add each sentence as a document
    sentences.forEach(sentence => tfidf.addDocument(sentence));
    
    // Calculate sentence scores
    const scoredSentences = sentences.map((sentence, index) => {
        let score = 0;
        
        // Get important terms from the sentence
        const terms = sentence.toLowerCase().match(/\b\w+\b/g) || [];
        
        // Score based on TF-IDF
        terms.forEach(term => {
            score += tfidf.tfidf(term, index);
        });
        
        // Boost score for sentences with focus keywords
        if (focus) {
            const focusTerms = focus.toLowerCase().split(/\s+/);
            focusTerms.forEach(term => {
                if (sentence.toLowerCase().includes(term)) {
                    score *= 1.5;
                }
            });
        }
        
        // Boost score for sentences with important indicators
        const importantPhrases = ['in conclusion', 'therefore', 'thus', 'hence', 'consequently', 'as a result', 'important', 'significant', 'key', 'main'];
        importantPhrases.forEach(phrase => {
            if (sentence.toLowerCase().includes(phrase)) {
                score *= 1.3;
            }
        });
        
        return {
            index,
            sentence: sentence.trim(),
            score,
            wordCount: sentence.split(/\s+/).length
        };
    });
    
    // Sort by score
    scoredSentences.sort((a, b) => b.score - a.score);
    
    // Select sentences while respecting word count
    let selectedSentences = [];
    let wordCount = 0;
    let minWords = targetWords * 0.8;
    let maxWords = targetWords * 1.2;
    
    for (const scored of scoredSentences) {
        if (wordCount + scored.wordCount <= maxWords) {
            selectedSentences.push(scored);
            wordCount += scored.wordCount;
        }
        if (wordCount >= minWords) break;
    }
    
    // Sort back to original order for coherence
    selectedSentences.sort((a, b) => a.index - b.index);
    
    // Format the summary based on the requested format
    let summary;
    if (format === 'bullet_points') {
        // For bullet points, process each sentence as a separate point
        const points = selectedSentences.map(s => {
            // Clean up the sentence
            let point = s.sentence.trim();
            // Remove trailing period if it exists
            point = point.replace(/\.$/, '');
            // Add bullet point
            return point;
        });
        
        // Join points with bullet points and newlines
        summary = points.map(point => `• ${point}`).join('\n');
    } else {
        // For paragraph format, join sentences with proper spacing
        summary = selectedSentences
            .map(s => s.sentence)
            .join('. ') + '.';
    }

    // Calculate final word count
    wordCount = summary.split(/\s+/).length;
    
    logger.debug(`Summarization complete: originalWords=${text.split(/\s+/).length}, summaryWords=${wordCount}, format=${format}`);
    return { 
        summary,
        word_count: wordCount,
        format: format // Include format in response
    };
};

// Helper function to extract text content from HTML
const extractTextFromHTML = (html) => {
    const $ = cheerio.load(html);
    
    // Remove script and style elements
    $('script, style').remove();
    
    // Get text from paragraphs and headings
    const paragraphs = $('p, h1, h2, h3, h4, h5, h6').map((i, el) => $(el).text()).get();
    
    // Join paragraphs with newlines
    return paragraphs.join('\n\n').trim();
};

// Add language support to summarization endpoint
app.post("/api/summarize", authenticateToken, async (req, res) => {
    const { text, url, wordCount, focus, style, format = 'paragraph', language = 'en', title = 'Untitled Summary' } = req.body;
    logger.info(`Received request: type=${url ? 'URL' : (req.files?.file ? 'File' : 'Text')}, language=${language}, format=${format}`);
    
    // Validate language
    if (!supportedLanguages[language]) {
        return res.status(400).json({ 
            error: "Invalid language", 
            details: `Language '${language}' is not supported. Supported languages: ${Object.keys(supportedLanguages).join(', ')}`
        });
    }
    
    let inputText = text;
    let wasTranslated = false;
    let sourceType = text ? 'text' : (url ? 'url' : 'file');
    
    try {
        // Ensure user is authenticated and ID is available
        if (!req.user || !req.user.id) {
            throw new Error('User authentication required');
        }

        // Process input from various sources
        if (!inputText) {
            if (url) {
                logger.debug(`Fetching content from URL: ${url}`);
                const response = await axios.get(url);
                const htmlContent = response.data;
                inputText = extractTextFromHTML(htmlContent);
                
                if (!inputText) {
                    throw new Error('No readable content found in URL');
                }
                logger.debug(`Successfully extracted ${inputText.length} characters from URL`);
            } else if (req.files && req.files.file) {
                const file = req.files.file;
                logger.debug('Processing uploaded file:');
                logger.debug(`- Name: ${file.name}`);
                logger.debug(`- Size: ${file.size} bytes`);
                logger.debug(`- MIME Type: ${file.mimetype}`);
                
                inputText = await processFile(file);
                logger.debug(`Successfully extracted ${inputText.length} characters from file`);
            } else {
                throw new Error('Text, URL, or file is required');
            }
        }

        if (!inputText || inputText.trim().length === 0) {
            throw new Error('No text to summarize');
        }

        logger.debug(`Processing ${sourceType} input with ${inputText.length} characters in ${language} language`);

        // Handle language processing
        let processedInput = inputText;
        let translatedToEnglish = null;

        if (language !== 'en') {
            // First translate to English for better summarization
            logger.debug('Translating input to English for processing');
            translatedToEnglish = await processLanguage(inputText, 'en');
            processedInput = translatedToEnglish.text;
            wasTranslated = true;
            logger.debug(`Translated ${inputText.length} characters to English`);
        }

        // Perform summarization in English with format
        const targetWords = wordCount || 130;
        logger.debug(`Summarizing text with target ${targetWords} words in ${format} format`);
        const result = summarizeText(processedInput, targetWords, focus, format);
        let { summary: summarizedText, word_count: actualWordCount } = result;

        // If language is not English, translate the summary
        if (language !== 'en') {
            logger.debug(`Translating summary to ${language}`);
            try {
                const translatedSummary = await translateText(summarizedText, { 
                    from: 'en',
                    to: language 
                });
                
                // For bullet points, we need to preserve the format after translation
                if (format === 'bullet_points') {
                    // Split the translated text and reformat as bullet points
                    const translatedPoints = translatedSummary.split(/[.。]/).filter(p => p.trim());
                    summarizedText = translatedPoints.map(point => `• ${point.trim()}`).join('\n');
                } else {
                    summarizedText = translatedSummary;
                }
                
                // Recalculate word count for non-English summary
                actualWordCount = summarizedText.split(/\s+/).length;
                logger.debug(`Translated summary to ${language}, new word count: ${actualWordCount}`);
            } catch (translationError) {
                logger.error(`Translation error: ${translationError.message}`);
                throw new Error(`Failed to translate summary to ${supportedLanguages[language]}`);
            }
        }
        
        logger.info(`Summarization complete: source=${sourceType}, original=${inputText.length} chars, summary=${summarizedText.length} chars, language=${language}`);

        const summary = new Summary({
            userId: req.user.id,
            originalText: inputText,
            summarizedText,
            wordCount: actualWordCount,
            focus,
            style,
            format,
            language,
            title,
            sourceType,
            createdAt: new Date(),
            metadata: {
                reading_time_seconds: Math.ceil(actualWordCount / 200 * 60),
                original_length: inputText.length,
                summary_length: summarizedText.length,
                was_translated: language !== 'en',
                key_terms: extractKeyTerms(inputText)
            }
        });

        // Save the summary to MongoDB
        await summary.save();
        logger.debug(`Summary saved to database with ID: ${summary._id}`);

        res.json({ 
            summary: summarizedText, 
            wordCount: actualWordCount,
            metadata: {
                reading_time_seconds: Math.ceil(actualWordCount / 200 * 60),
                word_count: actualWordCount,
                key_terms: extractKeyTerms(inputText),
                original_length: inputText.length,
                summary_length: summarizedText.length,
                target_language: language,
                was_translated: language !== 'en',
                source_type: sourceType,
                format: format,
                summary_id: summary._id
            }
        });
    } catch (error) {
        logger.error(`Processing error (${sourceType}): ${error.message}`);
        res.status(500).json({ 
            error: "Processing failed", 
            details: error.message,
            type: error.name,
            source_type: sourceType
        });
    }
});

// Helper function to extract key terms
const extractKeyTerms = (text) => {
    const words = text.toLowerCase().match(/\b\w+\b/g) || [];
    const wordFreq = {};
    words.forEach(word => {
        if (word.length > 3) { // Only count words longer than 3 characters
            wordFreq[word] = (wordFreq[word] || 0) + 1;
        }
    });
    return Object.entries(wordFreq)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5); // Return top 5 terms
};

// Get user's summaries
app.get("/api/summaries", authenticateToken, async (req, res) => {
    try {
        const summaries = await Summary.find({ userId: req.user.id })
            .sort({ createdAt: -1 }) // Sort by newest first
            .limit(10); // Limit to last 10 summaries
        res.json(summaries);
    } catch (error) {
        logger.error("Error fetching summaries: %s", error.message);
        res.status(500).json({ message: "Error fetching summaries", details: error.message });
    }
});

// Get individual summary
app.get("/api/summaries/:id", authenticateToken, async (req, res) => {
    try {
        logger.debug(`Fetching summary ${req.params.id} for user ${req.user.id}`);
        
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            logger.warn(`Invalid summary ID format: ${req.params.id}`);
            return res.status(400).json({ message: "Invalid summary ID format" });
        }

        const summary = await Summary.findOne({ 
            _id: req.params.id,
            userId: req.user.id 
        });

        if (!summary) {
            logger.warn(`Summary ${req.params.id} not found for user ${req.user.id}`);
            return res.status(404).json({ message: "Summary not found" });
        }

        logger.debug(`Successfully retrieved summary ${req.params.id}`);
        res.json(summary);
    } catch (error) {
        logger.error(`Error fetching summary: ${error.message}`);
        res.status(500).json({ message: "Error fetching summary", details: error.message });
    }
});

// Health check
app.get("/api/check", (req, res) => {
    res.json({ status: "OK", message: "Server is running, no Python dependencies required" });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => logger.info("Server running on port %d", PORT));