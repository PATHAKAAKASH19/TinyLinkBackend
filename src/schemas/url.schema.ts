import z from "zod";


// ✔ javascript: injection
// ✔ ftp abuse
// ✔ SSRF to localhost
// ✔ internal network scanning
// ✔ invalid garbage input

export const urlSchema = z.object({
  body: {
    url: z
      .url("Invalid URL format")
      .max(2048, "URL too long")
      .refine((val) => {
        const parsed = new URL(val);
        return ["http:", "https:"].includes(parsed.protocol);
      }, "Only HTTP and HTTPS URLs allowed")
      .refine((val) => {
        const parsed = new URL(val);
        const hostname = parsed.hostname;

        const isPrivate =
          hostname === "localhost" ||
          hostname.startsWith("127.") ||
          hostname.startsWith("10.") ||
          hostname.startsWith("192.168.") ||
          hostname.startsWith("172.");

        return !isPrivate;
      }, "Private or local URLs are not allowed"),
  },
});


export type UrlInput = z.infer<typeof urlSchema>["body"]