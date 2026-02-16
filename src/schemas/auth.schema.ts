import { z } from "zod";

export const registerSchema = z.object({
  body: z.object({
    email: z.email("Invaide email address"),
    password: z
      .string()
      .min(8, "Password must be at least 8 character")
      .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
      .regex(/[a-z]/, "Password must contain at least one lowercase letter")
      .regex(/[0-9]/, "Password must contain at least one number")
      .regex(
        /[^A-Za-z0-9]/,
        "Password must contain at least one special character")
     .max(12, "Password must be at most 12 character"),
    name:z.string()
    .min(2, 'Name must be at least 3 characters')
    .max(50, "Name must be at most 50 characters")
    .optional()
  }),
});



export const loginSchema = z.object({
    body: z.object({
        email:z.email("Invalid email address"),
        password:z.string().min(1, "Password is required")
    })
})

export type RegisterInput = z.infer<typeof registerSchema>['body']

export type LoginInput = z.infer<typeof loginSchema>['body']