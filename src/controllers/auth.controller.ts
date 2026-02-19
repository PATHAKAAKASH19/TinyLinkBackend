import { Request, Response } from "express";
import { prisma } from "../lib/prisma";
import jwt from "jsonwebtoken";
import { registerSchema, loginSchema } from "../schemas/auth.schema";
import bcrypt from "bcrypt";
import { generateOtp, sendOtpEmail } from "../utils/mailer";
import { success } from "zod";
import { generateCodeVerifier, generateState, Google } from "arctic";

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

async function changePassword(req: Request, res: Response) {
  try {
    const { oldPassword, newPassword, userId } = req.body;

    const salt = await bcrypt.genSalt(10);

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

    const hashedpassword = await bcrypt.hash(oldPassword, salt);

    if (hashedpassword !== userPresent.password) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, salt);

    const updateUserPassword = await prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        password: hashedNewPassword,
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

async function requestPasswordReset(req: Request, res: Response) {
  try {
    const { email } = req.body;

    if (!email) {
      return res.json(400).json({
        success: false,
        message: "Email is required",
      });
    }

    const user = await prisma.user.findUnique({
      where: {
        email: email,
      },
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "user not found",
      });
    }

    const otp = generateOtp();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await prisma.otp.deleteMany({
      where: {
        email: email,
      },
    });

    await prisma.otp.create({
      data: {
        otp: otp,
        email: email,
        expiresAt: expiresAt,
        type: `PASSWORD_RESET`,
      },
    });

    await sendOtpEmail(email, otp);

    return res.status(200).json({
      success: false,
      message: "OTP send successfully to your email",
    });
  } catch (error) {
    return res.status(500).json({
      success: true,
      message: "Internal server error",
    });
  }
}

async function verifyOtp(req: Request, res: Response) {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        message: "Email and OTP are required",
      });
    }

    const otpRecord = await prisma.otp.findFirst({
      where: {
        email: email,
        otp: otp,
        type: "PASSWORD_RESET",
        verified: false,
        expiresAt: {
          gt: new Date(),
        },
      },
    });

    if (!otpRecord) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired OTP",
      });
    }

    await otpRecord.update({
      where: {
        id: otpRecord.id,
      },

      data: {
        verified: true,
      },
    });

    const resetToken = jwt.sign(
      {
        email,
      },
      process.env.ACCESS_TOKEN_SECRET!,
      {
        expiresIn: "20m",
        issuer: "urlShortner-backend",
        audience: "urlShortner-client",
      },
    );

    res.status(200).json({
      success: true,
      message: "OTP verified successfully",
      resetToken,
    });
  } catch (error) {
    return res.status(500).json({
      success: true,
      message: "Internal server error",
    });
  }
}

async function resetPassword(req: Request, res: Response) {
  try {
    const { newPassword, email } = req.body;

    const salt = await bcrypt.genSalt(10);

    const hashedPassword = await bcrypt.hash(newPassword, salt);

    const updateUser = await prisma.user.update({
      where: {
        id: email,
      },
      data: {
        password: hashedPassword,
      },
    });

    await prisma.oTP.deleteMany({
      where: { email: email },
    });

    return res.status(200).json({
      success: true,
      message: "Password changes successfully",
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Failed to reset Password",
    });
  }
}

async function requestGoogleAuth(req: Request, res: Response) {
  try {
    const state = generateState();
    const codeVerifier = generateCodeVerifier();

    const googleAuth = new Google(
      process.env.GOOGLE_CLIENT_ID!,
      process.env.GOOGLE_CLIENT_SECRET!,
      process.env.GOOGLE_REDIRECT_URI!,
    );

    const SCOPES = ["openid", "email", "profile"];

    const authorizationUrl = googleAuth.createAuthorizationURL(
      state,
      codeVerifier,
      SCOPES,
    );

    res.cookie("oauth_state", state, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: 10 * 60 * 1000, // 10 minutes
    });
    res.cookie("oauth_code_verifier", codeVerifier, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: 10 * 60 * 1000,
    });

    return res.redirect(authorizationUrl.toString());
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Google Auth failed",
    });
  }
}

async function googleLogin(req: Request, res: Response) {
  const code = req.query.code as string | null;
  const state = req.query.state as string | null;

  const storedState = req.cookies?.oauth_state ?? null;
  const storedCodeVerifier = req.cookies?.oauth_code_verifier ?? null;

  if (
    !code ||
    !state ||
    !storedState ||
    !storedCodeVerifier ||
    state !== storedState
  ) {
    console.error("OAuth callback validation failed:", {
      hasCode: !!code,
      hasState: !!state,
      hasStoredState: !!storedState,
      hasCodeVerifier: !!storedCodeVerifier,
      stateMatch: state === storedState,
    });
    return res.redirect(
      `${process.env.CLIENT_URL}/login?error=invalid_request`,
    );
  }
  try {
    res.clearCookie("oauth_state");
    res.clearCookie("oauth_code_verifier");
    const googleAuth = new Google(
      process.env.GOOGLE_CLIENT_ID!,
      process.env.GOOGLE_CLIENT_SECRET!,
      process.env.GOOGLE_REDIRECT_URI!,
    );

    const tokens = await googleAuth.validateAuthorizationCode(
      code,
      storedCodeVerifier,
    );


    const accessToken = tokens.accessToken();

    const userInfoResponse = await fetch(
      `https://www.googleapis.com/oauth2/v2/userinfo`,
      {
        headers: { Authorization: `Bearer ${accessToken}` },
      }
    );

    if (!userInfoResponse.ok) {
       throw new Error('failed to fetch user info from google')
    }

    const userInfo = await userInfoResponse.json()

    const { id: googleId, email, name } = userInfo;

    if (!email) {
      throw new Error("Failed to fetch user email from google")
    }


    let user = await prisma.user.findUnique({
      where: {
        email:email
      }
    })

    if (user) {
      const updateUser = await prisma.user.update({
        where: {
          email:email
        },
        data:{
           googleId:googleId
        }
      })
    } else {
      
    }
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Google Auth failed",
    });
  }
}

async function verifyEmail(req: Request, res: Response) {
  try {
    const { email } = req.body;
  } catch (error) {}
}

export {
  changePassword,
  signup,
  login,
  logout,
  requestPasswordReset,
  verifyOtp,
  verifyEmail,
  resetPassword,
};
