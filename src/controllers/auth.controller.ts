import { Request, Response } from "express";
import { prisma } from "../lib/prisma";
import jwt from "jsonwebtoken";
import { registerSchema, loginSchema } from "../schemas/auth.schema";
import bcrypt from "bcrypt";
import { success } from "zod";

async function signup(req: Request, res: Response) {
  try {
    const { email, password } = req.body;

    const user = await prisma.user.findUnique({
      where: {
        email: email,
      },
      select: {
        id: true,
      },
    });

    if (user) {
      return res.status(409).json({
        success: false,
        message: "email is already present",
      });
    }

    const saltRounds = 10;

    const hashedpassword = await bcrypt.hash(password, saltRounds);

    const createNewUser = await prisma.user.create({
      data: {
        email: email,
        password: hashedpassword,
      },

      select: {
        id: true,
      },
    });

    if (process.env.AUTO_LOGIN_AFTER_SIGNUP === "true") {
      const accessToken = jwt.sign(
        {
          userId: createNewUser.id,
          email: email,
          type: "accessToken",
        },
        process.env.ACCESS_TOKEN_SECRET!,
        {
          expiresIn: "1d",
          issuer: "urlShortner-backend",
          audience: "urlShortner-client",
        },
      );
      const refreshToken = jwt.sign(
        {
          userId: createNewUser.id,
          email: email,
          type: "refreshToken",
        },
        process.env.REFRESH_TOKEN_SECRET!,
        {
          expiresIn: "7d",
          issuer: "urlShortner-backend",
          audience: "urlShortner-client",
        },
      );

      await prisma.refreshToken.create({
        data: {
          token: refreshToken,
          userId: createNewUser.id,
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        },
      });

      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        path: "/api/v1/auth",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      return res.status(200).json({
        success: true,
        message: "user register successfully",
        accessToken: accessToken,
      });
    }
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "internal server error",
    });
  }
}

async function login(req: Request, res: Response) {
  try {
    const { email, password } = req.body;

    const userPresent = await prisma.user.findFirst({
      where: {
        email: email,
      },
    });

    if (!userPresent) {
      return res.status(404).json({
        success: true,
        message: "user not found",
      });
    }

    const saltRounds = 10;

    const isPasswordValid = await bcrypt.hash(password, saltRounds);

    if (isPasswordValid !== userPresent.password) {
      return res.status(401).json({
        success: true,
        message: "Invalid credentials",
      });
    }

    const accessToken = jwt.sign(
      {
        userId: userPresent.id,
        email: email,
        type: "accessToken",
      },
      process.env.ACCESS_TOKEN_SECRET!,
      {
        expiresIn: "1d",
        issuer: "urlShortner-backend",
        audience: "urlShortner-client",
      },
    );
    const refreshToken = jwt.sign(
      {
        userId: userPresent.id,
        email: email,
        type: "refreshToken",
      },
      process.env.REFRESH_TOKEN_SECRET!,
      {
        expiresIn: "7d",
        issuer: "urlShortner-backend",
        audience: "urlShortner-client",
      },
    );

    await prisma.refreshToken.create({
      data: {
        token: refreshToken,
        userId: userPresent.id,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      path: "/api/v1/auth",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      success: true,
      message: "user register successfully",
      accessToken: accessToken,
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
}

async function logout(req: Request, res: Response) {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: "No refresh token provided",
      });
    }

    await prisma.refreshToken.deleteMany({
      where: {
        token: refreshToken,
      },
    });

    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      path: "/api/v1/auth",
    });

    return res.status(200).json({
      success: true,
      message: "User logged out successfully",
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
}

async function generateRefreshToken() {
  try {
    
  } catch (error) {
    
  }
}

async function verifyOtp(req: Request, res: Response) {
    try {
      
        
       const {} = 
    } catch (error) {
      return res.status(500).json({
        success: true,
        message:"Internal server error"
      })
  }
}

async function verifyEmail(req: Request, res: Response) {
  try {
    
  } catch (error) {
    
  }
}


async function resendVerification(req: Request, res: Response) {}

async function resetPassword(req: Request, res: Response) {
  try {
  } catch (error) {}
}

async function changePassword(req: Request, res: Response) {
  try {
    const { oldPassword, newPassword, userId } = req.body;

    const saltRounds = 10;

    const userPresent = await prisma.user.findUnique({
      where: {
        id: userId,
      },
    });

    if (!userPresent) {
      return res.status(404).json({
        success: false,
        message: "user not found",
      });
    }

    const hashedpassword = await bcrypt.hash(oldPassword, saltRounds);

    if (hashedpassword !== userPresent.password) {
      return res.status(401).json({
        success: false,
        message: "Invalid creadentials",
      });
    }

    const hashedNewPassoword = await bcrypt.hash(newPassword, saltRounds);

    const updateUserPassword = await prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        password: hashedNewPassoword,
      },
    });

    return res.status(200).json({
      success: true,
      message: "password changed succesfully",
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
}

export {
  changePassword,
  signup,
  login,
  logout,
  forgetPassword,
  verifyEmail,
  resendVerification,
  resetPassword,
};
