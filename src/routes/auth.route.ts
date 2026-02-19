import express from "express";
import {
  signup,
  logout,
  login,
  resetPassword,
  requestPasswordReset,
  verifyOtp,
  verifyEmail,
  changePassword,
  requestGoogleAuth,
  googleAuthCallback,
  rotateToken
} from "../controllers/auth.controller";
const router = express.Router();

router.post("/signup", signup);
router.post("/login", login);
router.post("/logout", logout);
router.post("/refresh", rotateToken);
router.post("/change-password", changePassword);
router.post("/forget-password", requestPasswordReset);
router.post("/verify-otp", verifyOtp);
router.post("/resend-otp", requestPasswordReset);
router.post("/reset-password", resetPassword);
router.post("/verify-email", verifyEmail);
router.post("/google",requestGoogleAuth );
router.post("/google/callback", googleAuthCallback);

export default router;
