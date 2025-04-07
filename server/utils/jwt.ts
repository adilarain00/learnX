require("dotenv").config();
import { Iuser } from "../models/user.model";
import { Response } from "express";
import { redis } from "./redis";

// ✅ Add 'path' to interface (TypeScript-safe)
interface ITokenOptions {
  expires: Date;
  maxAge: number;
  httpOnly: boolean;
  sameSite: "lax" | "strict" | "none" | undefined;
  secure?: boolean;
  path?: string;
}

// ✅ Parse token expiry values with fallback (in seconds or days)
const accessTokenExpire = parseInt(process.env.ACCESS_TOKEN_EXPIRE || "300", 10); // 5 mins
const refreshTokenExpire = parseInt(process.env.REFRESH_TOKEN_EXPIRE || "3", 10); // 3 days

// ✅ Access Token Cookie Options
export const accessTokenOptions: ITokenOptions = {
  expires: new Date(Date.now() + accessTokenExpire * 1000),
  maxAge: accessTokenExpire * 1000,
  httpOnly: true,
  sameSite: "none",
  secure: process.env.NODE_ENV === "production", // only secure in prod
};

// ✅ Refresh Token Cookie Options
export const refreshTokenOptions: ITokenOptions = {
  expires: new Date(Date.now() + refreshTokenExpire * 24 * 60 * 60 * 1000),
  maxAge: refreshTokenExpire * 24 * 60 * 60 * 1000,
  httpOnly: true,
  sameSite: "none",
  secure: process.env.NODE_ENV === "production", // only secure in prod
  path: "/api/v1/refresh", // helpful for targeted cookie usage
};

// ✅ Send Token + Save to Redis + Return Response
export const sendToken = (user: Iuser, statusCode: number, res: Response) => {
  const accessToken = user.SignAccessToken();
  const refreshToken = user.SignRefreshToken();

  // ✅ Upload session to Redis
  redis.set(user._id, JSON.stringify(user));

  // ✅ Set Cookies
  res.cookie("access_token", accessToken, accessTokenOptions);
  res.cookie("refresh_token", refreshToken, refreshTokenOptions);

  // ✅ Send response
  res.status(statusCode).json({
    success: true,
    user,
    accessToken,
  });
};
