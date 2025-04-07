import { updateAccessToken } from "../../controllers/user.controller";
import { Request, Response, NextFunction } from "express";
import { CatchAsyncError } from "./catchAsyncErrors";
import jwt, { JwtPayload } from "jsonwebtoken";
import ErrorHandler from "../ErrorHandler";
import { redis } from "../redis";

export const isAuthenticated = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    const access_token = req.cookies.access_token as string;

    if (!access_token) {
      return next(new ErrorHandler("Please login to access this resource", 401));
    }

    let decoded: JwtPayload;

    try {
      // ✅ Use verify, not decode, to ensure token is valid and signed
      decoded = jwt.verify(access_token, process.env.ACCESS_TOKEN!) as JwtPayload;
    } catch (err: any) {
      // ✅ If token is expired, try to refresh
      if (err.name === "TokenExpiredError") {
        try {
          console.log("Access token expired, attempting to refresh...");
          await updateAccessToken(req, res, next);
          return; // ✅ Don't proceed to next middleware — it's handled in updateAccessToken
        } catch (refreshError) {
          return next(refreshError);
        }
      } else {
        return next(new ErrorHandler("Invalid access token", 401));
      }
    }

    // ✅ Ensure we have a decoded token with a valid ID
    if (!decoded || !decoded.id) {
      return next(new ErrorHandler("Invalid access token payload", 401));
    }

    // ✅ Fetch user session from Redis
    const user = await redis.get(decoded.id);
    if (!user) {
      return next(new ErrorHandler("User session expired. Please login again.", 401));
    }

    req.user = JSON.parse(user);
    next();
  }
);

export const authorizeRoles = (...roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!roles.includes(req.user?.role || "")) {
      return next(
        new ErrorHandler(
          `Role: ${req.user?.role} is not allowed to access this resource`,
          403
        )
      );
    }
    next();
  };
};
