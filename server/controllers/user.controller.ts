import { CatchAsyncError } from "../utils/middleware/catchAsyncErrors";
import { Request, Response, NextFunction } from "express";
import userModel, { Iuser } from "../models/user.model";
import jwt, { JwtPayload, Secret } from "jsonwebtoken";
import { redis } from "../utils/redis";
import {
  accessTokenOptions,
  refreshTokenOptions,
  sendToken,
} from "../utils/jwt";
import {
  getAllUsersService,
  getUserById,
  updateUserRoleservice,
} from "../services/user.services";

import ErrorHandler from "../utils/ErrorHandler";
import sendmail from "../utils/sendMail";
import cloudinary from "cloudinary";

//register user
interface IRegisterationBody {
  name: string;
  email: string;
  password: string;
  avatar?: string;
}

export const registerationUser = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { name, email, password } = req.body;

      const isEmailExist = await userModel.findOne({ email: email });
      if (isEmailExist) {
        return next(new ErrorHandler("Email already exist", 400));
      }

      const user: IRegisterationBody = {
        name,
        email,
        password,
      };

      const activationToken = createActivationToken(user);
      const activationCode = activationToken.activationCode;
      const data = { user: { name: user.name }, activationCode };

      try {
        await sendmail({
          email: user.email,
          subject: "Activate your account",
          template: "activation-mails.ejs",
          data,
        });

        res.status(201).json({
          success: true,
          message: `Please check your email: ${user.email} to activate your account`,
          activationToken: activationToken.token,
        });
      } catch (error) { }
    } catch (error: any) {
      return next(new ErrorHandler(error.message, 400));
    }
  }
);

interface IactivationToken {
  token: string;
  activationCode: string;
}

// jwt token otp
export const createActivationToken = (user: any): IactivationToken => {
  const activationCode = Math.floor(100000 + Math.random() * 900000).toString();

  const token = jwt.sign(
    { user, activationCode },
    process.env.ACTIVATION_SECRET as Secret,
    { expiresIn: "5m" }
  );

  return { token, activationCode };
};


interface IActivationRequest {
  activationToken: string;
  activationCode: string;
}

interface DecodedToken {
  user: Iuser;
  activationCode: string;
}

export const activateUser = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    console.log("🔹 Received Activation Request");
    console.log("Request Body:", req.body);

    const { activationToken, activationCode }: IActivationRequest = req.body;

    if (!activationToken || !activationCode) {
      return next(new ErrorHandler("Activation token and code are required", 400));
    }

    let decoded: DecodedToken;
    try {
      decoded = jwt.verify(activationToken, process.env.ACTIVATION_SECRET as string) as DecodedToken;
    } catch (error) {
      return next(new ErrorHandler("Invalid activation token", 400));
    }

    if (decoded.activationCode !== activationCode) {
      return next(new ErrorHandler("Invalid activation code", 404));
    }

    const { name, email, password } = decoded.user;

    const existingUser = await userModel.findOne({ email });
    if (existingUser) {
      return next(new ErrorHandler("Email already exists", 400));
    }

    console.log("✅ Creating New User...");
    const newUser = new userModel({
      name,
      email,
      password,
      avatar: "DEFAULT_AVATAR",
    });

    await newUser.save();
    console.log("✅ User Created Successfully:", newUser);

    res.status(201).json({
      success: true,
      message: "User activated successfully",
      user: newUser,
    });
  } catch (error: any) {
    console.error("❌ Activation Error:", error.message);
    return next(new ErrorHandler(error.message, 400));
  }
};

interface IloginRequest {
  email: string;
  password: string;
}

export const loginUser = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { email, password } = req.body as IloginRequest;

      if (!email || !password) {
        return next(
          new ErrorHandler("Please enter your email and password", 400)
        );
      }

      const user = await userModel.findOne({ email }).select("+password");

      if (!user) {
        return next(new ErrorHandler("Invalid email or password", 400));
      }

      const isPasswordMatch = await user.comparepassword(password);

      if (!isPasswordMatch) {
        return next(new ErrorHandler("Invalid email and password", 400));
      }
      sendToken(user, 201, res);
    } catch (error: any) {
      return next(new ErrorHandler(error.message, 400));
    }
  }
);

export const logoutUser = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      res.cookie("access_token", "", { maxAge: 1 });
      res.cookie("refresh_token", "", { maxAge: 1 });
      const userId = req.user?._id || "";

      redis.del(userId);
      res.status(200).json({
        success: true,
        message: "Logged out successfully",
      });
    } catch (error: any) {
      return next(new ErrorHandler(error.message, 400));
    }
  }
);

// Refresh token controller
export const updateAccessToken = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    const refresh_token = req.cookies.refresh_token as string;

    if (!refresh_token) {
      return next(new ErrorHandler("Refresh token missing", 401));
    }

    try {
      // ✅ Verify the refresh token
      const decoded = jwt.verify(
        refresh_token,
        process.env.REFRESH_TOKEN as string
      ) as JwtPayload;

      if (!decoded || !decoded.id) {
        return next(new ErrorHandler("Invalid refresh token", 401));
      }

      // ✅ Fetch the user session from Redis
      const session = await redis.get(decoded.id);
      if (!session) {
        return next(
          new ErrorHandler("Session expired. Please log in again.", 401)
        );
      }

      const user = JSON.parse(session);

      // ✅ Create new tokens
      const newAccessToken = jwt.sign(
        { id: user._id },
        process.env.ACCESS_TOKEN as string,
        { expiresIn: process.env.ACCESS_TOKEN_EXPIRE || "5m" }
      );

      const newRefreshToken = jwt.sign(
        { id: user._id },
        process.env.REFRESH_TOKEN as string,
        { expiresIn: process.env.REFRESH_TOKEN_EXPIRE || "3d" }
      );

      // ✅ Re-assign user to req.user
      req.user = user;

      // ✅ Send new cookies
      res.cookie("access_token", newAccessToken, accessTokenOptions);
      res.cookie("refresh_token", newRefreshToken, refreshTokenOptions);

      // ✅ Refresh session expiry in Redis (7 days)
      await redis.set(user._id, JSON.stringify(user), "EX", 7 * 24 * 60 * 60);

      console.log("Access token refreshed successfully for user:", user._id);

      // ✅ Continue to next middleware
      return next();
    } catch (err: any) {
      if (err.name === "TokenExpiredError") {
        return next(new ErrorHandler("Refresh token expired. Please log in again.", 401));
      }

      return next(new ErrorHandler("Failed to refresh access token", 400));
    }
  }
);


//get user information

export const getuserInfo = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    const user = req.user;
    const accessToken = req.cookies.access_token; // Optional

    res.status(200).json({
      success: true,
      user,
      accessToken, // Include if frontend expects it
    });
  }
);


//social auth
interface IsocialAuthBody {
  email: string;
  name: string;
  avatar: string;
}
export const socialAuth = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { email, name, avatar } = req.body as IsocialAuthBody;
      const user = await userModel.findOne({ email });
      if (!user) {
        const newUser = await userModel.create({ email, name, avatar });
        sendToken(newUser, 200, res);
      } else {
        sendToken(user, 200, res);
      }
    } catch (error) { }
  }
);

//update user  info
interface IupdateUserInfo {
  name: string;
  email: string;
}

export const updateUserInfo = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { name } = req.body as IupdateUserInfo;

      const userId = req.user?._id;

      const user = await userModel.findById(userId.toString());

      if (name && user) {
        user.name = name;
      }
      await user?.save();

      await redis.set(userId, JSON.stringify(user));

      res.status(201).json({
        success: true,
        user,
      });
    } catch (error) { }
  }
);

interface IupdatePassword {
  oldPassword: string;
  newPassword: string;
}
//change password
export const updatePassword = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { oldPassword, newPassword } = req.body as IupdatePassword;
      if (!oldPassword || !newPassword) {
        return next(new ErrorHandler("Please enter old and new password", 400));
      }
      const user = await userModel.findById(req.user?._id).select("+password");

      if (user?.password === undefined) {
        return next(new ErrorHandler("Invalid old Password", 400));
      }

      const isPasswordMatch = await user?.comparepassword(oldPassword);

      if (!isPasswordMatch) {
        return next(new ErrorHandler("Invalid old Password", 400));
      }

      user.password = newPassword;

      await user.save();
      await redis.set(req.user?._id, JSON.stringify(user));

      res.status(201).json({
        user,
        success: true,
      });
    } catch (error: any) {
      return next(new ErrorHandler(error.message, 400));
    }
  }
);

// update profile picture
interface IUpdateProfilePicture {
  avatar: string;
}
export const updateProfilePicture = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { avatar } = req.body;

      const userId = req.user?._id;

      const user = await userModel.findById(userId);

      if (avatar && user) {
        if (user?.avatar?.public_id) {
          await cloudinary.v2.uploader.destroy(user?.avatar?.public_id);

          const myCloud = await cloudinary.v2.uploader.upload(avatar, {
            folder: "avatars",
            width: 150,
          });
          user.avatar = {
            public_id: myCloud.public_id,
            url: myCloud.secure_url,
          };
        } else {
          const myCloud = await cloudinary.v2.uploader.upload(avatar, {
            folder: "avatars",
            width: 150,
          });

          user.avatar = {
            public_id: myCloud.public_id,
            url: myCloud.secure_url,
          };
        }
      }

      await user?.save();

      await redis.set(userId, JSON.stringify(user));

      res.status(200).json({
        success: true,
        user,
      });
    } catch (error: any) {
      return next(new ErrorHandler(error.message, 400));
    }
  }
);

// get All Users ---> only for admin
export const getAllUsers = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      getAllUsersService(res);
    } catch (error: any) {
      return next(new ErrorHandler(error.message, 500));
    }
  }
);

// update user role
export const updateUserRole = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { email, role } = req.body;
      const isUserExist = await userModel.findOne({ email });
      if (isUserExist) {
        const id = isUserExist._id;
        updateUserRoleservice(res, id, role);
      } else {
        res.status(400).json({
          success: false,
          message: "User not found",
        });
      }
    } catch (error: any) {
      return next(new ErrorHandler(error.message, 400));
    }
  }
);

// delete user - only for admin
export const deleteUser = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { id } = req.params;

      const user = await userModel.findById(id);

      if (!user) {
        return next(new ErrorHandler("User not found", 404));
      }

      await user.deleteOne({ id });
      await redis.del(id);

      res
        .status(200)
        .json({ success: true, message: "User deleted successfully" });
    } catch (error: any) {
      return next(new ErrorHandler(error.message, 500));
    }
  }
);
