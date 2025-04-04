import { updateAccessToken } from "../../controllers/user.controller";
import { Request, Response, NextFunction } from "express";
import { CatchAsyncError } from "./catchAsyncErrors";
import jwt, { JwtPayload } from "jsonwebtoken";
import ErrorHandler from "../ErrorHandler";
import { redis } from "../redis";

export const isAuthenticated = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    let access_token = req.cookies.access_token as string;

    // Fallback to Authorization header if cookie is not available
    if (!access_token && req.headers.authorization) {
      access_token = req.headers.authorization.split(" ")[1];
    }

    if (!access_token) {
      return next(new ErrorHandler("Please login to access this resource", 400));
    }

    try {
      const decoded = jwt.verify(access_token, process.env.JWT_SECRET!) as JwtPayload;

      if (!decoded) {
        return next(new ErrorHandler("Access token is not valid", 400));
      }

      // Check if the access token is expired
      if (decoded.exp && decoded.exp <= Date.now() / 1000) {
        try {
          await updateAccessToken(req, res, next); // Handle token refresh
        } catch (error) {
          return next(error);
        }
      } else {
        const user = await redis.get(decoded.id);

        if (!user) {
          return next(new ErrorHandler("Please login to access this resource", 400));
        }

        req.user = JSON.parse(user);
        next();
      }
    } catch (error) {
      return next(new ErrorHandler("Invalid token, please login again", 401));
    }
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
