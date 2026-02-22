import z from "zod/v4";
import dns from "dns/promises";

// ✔ javascript: injection
// ✔ ftp abuse
// ✔ SSRF to localhost
// ✔ internal network scanning
// ✔ invalid garbage input

export const urlSchema = z.object({
  body: z.object({
    url: z
      .url("Invalid URL format")
      .max(2048, "URL too long")
      .trim()
      .refine((val) => {
        try {
          const parsed = new URL(val);
          return ["http:", "https:"].includes(parsed.protocol);
        } catch (error) {
          return false;
        }
      }, "Only HTTP and HTTPS URLs allowed")
      .refine((val) => {
        try {
          const parsed = new URL(val);
          const hostname = parsed.hostname;

          const isPrivate =
            hostname === "localhost" ||
            hostname === "127.0.0.1" ||
            hostname.startsWith("127.") ||
            hostname.startsWith("10.") ||
            hostname.startsWith("192.168.") ||
            hostname.startsWith("172.16.") ||
            hostname.startsWith("172.17.") ||
            hostname.startsWith("172.18.") ||
            hostname.startsWith("172.19.") ||
            hostname.startsWith("172.20.") ||
            hostname.startsWith("172.21.") ||
            hostname.startsWith("172.22.") ||
            hostname.startsWith("172.23.") ||
            hostname.startsWith("172.24.") ||
            hostname.startsWith("172.25.") ||
            hostname.startsWith("172.26.") ||
            hostname.startsWith("172.27.") ||
            hostname.startsWith("172.28.") ||
            hostname.startsWith("172.29.") ||
            hostname.startsWith("172.30.") ||
            hostname.startsWith("172.31.") ||
            hostname === "::1";

          return !isPrivate;
        }catch {
          return false;
        }
      }, "Private or local URLs are not allowed")
      .refine(async (val) => {
            try {
              const parsed = new URL(val);
              await dns.lookup(parsed.hostname);
              return true;
            } catch {
              return false;
            }
      }, "Domain does not exist or is unreachable")
      .transform((val) => {
        try {
          const parsed = new URL(val);
          parsed.hash = "";
          parsed.hostname = parsed.hostname.toLowerCase();

          return parsed.toString();
        } catch {
          return val;
        }
      }),
  }),
});


export type UrlInput = z.infer<typeof urlSchema>["body"];
