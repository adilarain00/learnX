require("dotenv").config();
import { Iuser } from "../models/user.model";
import { Response } from "express";
import { redis } from "./redis";

// ✅ Cookie options type
interface ITokenOptions {
  expires: Date;
  maxAge: number;
  httpOnly: boolean;
  sameSite: "lax" | "strict" | "none" | undefined;
  secure?: boolean;
  path?: string;
}

// ✅ Expiry values from env or defaults
const accessTokenExpire = parseInt(process.env.ACCESS_TOKEN_EXPIRE || "300", 10); // 5 minutes
const refreshTokenExpire = parseInt(process.env.REFRESH_TOKEN_EXPIRE || "3", 10);  // 3 days

// ✅ Access Token Cookie Options (short-lived)
export const accessTokenOptions: ITokenOptions = {
  expires: new Date(Date.now() + accessTokenExpire * 1000),
  maxAge: accessTokenExpire * 1000,
  httpOnly: true,
  sameSite: "none", // ⛔ required for cross-site
  secure: process.env.NODE_ENV === "production", // ✅ must be true for 'None'
};

// ✅ Refresh Token Cookie Options (long-lived)
export const refreshTokenOptions: ITokenOptions = {
  expires: new Date(Date.now() + refreshTokenExpire * 24 * 60 * 60 * 1000),
  maxAge: refreshTokenExpire * 24 * 60 * 60 * 1000,
  httpOnly: true,
  sameSite: "none", // ⛔ required for cross-site
  secure: process.env.NODE_ENV === "production", // ✅ only over HTTPS
  path: "/api/v1/refresh", // 🔐 only send this cookie to refresh route
};

// ✅ Send tokens via cookies + save user to Redis
export const sendToken = (user: Iuser, statusCode: number, res: Response) => {
  const accessToken = user.SignAccessToken();
  const refreshToken = user.SignRefreshToken();

  // ✅ Store session in Redis (for logout/blacklist, etc.)
  redis.set(user._id, JSON.stringify(user));

  // ✅ Set cookies for tokens
  res.cookie("access_token", accessToken, accessTokenOptions);
  res.cookie("refresh_token", refreshToken, refreshTokenOptions);

  // ✅ Send response to frontend
  res.status(statusCode).json({
    success: true,
    user,
    accessToken,
  });
};
