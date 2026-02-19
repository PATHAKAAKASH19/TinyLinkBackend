import express, { Request, Response } from "express";
import cors from "cors";
import dotenv from "dotenv"
import cookieParser from "cookie-parser"
import authRoute from "./routes/auth.route"
import urlRoute from "./routes/links.route"

const app = express();

dotenv.config()

app.use(cookieParser())
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cors({
  origin: [process.env.FRONTEND_URL!],
  methods:["GET", "POST", "PUT", "DELETE"],
  credentials:true,
}))


app.get("/", (req: Request, res: Response) => {
  return res.status(200).json({
    message: "server is running at port 4000",
  });
});



app.use("/api/v1/auth", authRoute)
app.use("/api/v1/url", urlRoute)

app.listen(process.env.PORT, () => {
  console.log("server is running at port 3000");
});
