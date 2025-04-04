require("dotenv").config();
import { Request, Response, NextFunction } from "express";
import { ErrorMiddleWare } from "./utils/middleware/error";
import { rateLimit } from "express-rate-limit";

import notificationRouter from "./routes/notification.route";
import analyticsRouter from "./routes/analytics.route";
import courseRouter from "./routes/course.route";
import layoutRouter from "./routes/layout.route";
import orderRouter from "./routes/order.route";
import userRouter from "./routes/user.route";

import cookieParser from "cookie-parser";
import express from "express";
import cors from "cors";
import path from "path";
export const app = express();

// Middleware
app.use(express.json({ limit: "50mb" }));
app.use(cookieParser());
app.use(
  cors({
    origin: process.env.ORIGIN, // Ensure this is correctly set
    credentials: true, // Allow sending cookies
  })
);

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', 'https://learn-x-elearning.vercel.app'); 
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});

// ✅ API rate limiting (before routes)
const limiter = rateLimit({
  windowMs: 5 * 60 * 1000, // ⏳ 5 minutes instead of 15
  max: 500, // 🚀 Increase the request limit to 500
  message: "Too many requests, please try again later.", // Keep the message
  standardHeaders: "draft-7",
  legacyHeaders: false,
});

app.use(limiter);

// ✅ Serve static files from the build folder in production
const buildPath = path.join(__dirname, "../client/next");
app.use(express.static(buildPath));

// ✅ API Routes
app.use("/api/v1", userRouter);
app.use("/api/v1", courseRouter);
app.use("/api/v1", orderRouter);
app.use("/api/v1", notificationRouter);
app.use("/api/v1", analyticsRouter);
app.use("/api/v1", layoutRouter);

// ✅ Test Route
app.get("/test", (req: Request, res: Response) => {
  res.status(200).json({
    success: true,
    message: "API is working",
  });
});

app.get("/", (req, res) => {
  res.send("Backend is running...");
});

// ✅ Handle undefined routes
app.all("*", (req: Request, res: Response, next: NextFunction) => {
  const err = new Error(`Route ${req.originalUrl} not found`) as any;
  err.statusCode = 404;
  next(err);
});

// ✅ Global Error Handler Middleware
app.use(ErrorMiddleWare);
