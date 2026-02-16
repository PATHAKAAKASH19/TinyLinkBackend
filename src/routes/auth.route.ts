import express from "express";
import { signup, logout, login, resetPassword, forgetPassword, resendVerification, verifyEmail,changePassword } from "../controllers/auth.controller";
const router = express.Router();




router.post("/signup", signup)
router.post("/login", login)
router.post("/logout", logout)
router.post("/change-password", changePassword)
router.post("/reset-password", resetPassword)
router.post("/verify-email", verifyEmail)
router.post("/forget-password", forgetPassword)
router.post("/resend-verification", resendVerification)


export default router



