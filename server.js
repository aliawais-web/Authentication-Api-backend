import express from 'express';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { body } from 'express-validator';
import cors from 'cors';
import { connectDB } from './config/db.js';
import authRoutes from './routes/authRoutes.js';


dotenv.config();
connectDB();

const app = express();

// Security Middleware
app.use(helmet());
app.use(cors());
app.use(rateLimit({ windowMs: 10 * 60 * 1000, max: 100 }));

// Body & Cookie Parser
app.use(express.json());
app.use(cookieParser());


app.use('/api/auth', authRoutes);



// Routes Placeholder
app.get('/', (req, res) => {
  res.send('Auth API is running...');
});

// Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
