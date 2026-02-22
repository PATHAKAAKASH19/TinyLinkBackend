import { Request, Response } from "express";
import checkUrl from "../utils/url";
import { nanoid } from "nanoid";
import { prisma } from "../lib/prisma";
import { date } from "zod";

async function generateShortUrl(req: Request, res: Response) {
  try {
      const { url, userId, expiresAt } = req.body;
     
      const threatUrl = await checkUrl(url);


      
      const shortCode = nanoid(7);

      

      const record = await prisma.link.create({
          data: {
              url: url,
              shortcode: shortCode,
              user: userId,
              expiresAt:expiresAt
          }
      })


  } catch (error) {}
}

async function getAllUrl(req: Request, res: Response) {
    try {
        
    } catch (error) {
        
    }
}



async function urlRedirect(req: Request, res: Response) {
  try {
  } catch (error) {}
}

async function removeUrl(req: Request, res: Response) {
  try {
  } catch (error) {}
}

async function updateUrl(req: Request, res: Response) {
  try {
  } catch (error) {}
}

export { generateShortUrl };
