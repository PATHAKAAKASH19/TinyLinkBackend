import express from "express"
import { generateShortUrl } from "../controllers/links.controller"
const router = express.Router()

router.get("/",)
router.post("/",generateShortUrl)
router.delete("/")


 


export default router
