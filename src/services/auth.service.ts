// import {prisma} from "../lib/prisma"
// import bcrypt from "bcrypt";
// import jwt from "jsonwebtoken";
// import { RegisterInput } from "../schemas/auth.schema";



// async function  registerUser(userData:RegisterInput) {
//     try {
        
       
//         const {email, password, name} = userData;


//         const result = await prisma.user.findUnique({
//             where:{
//                 email:email
//             }
//         })
       
//         if(result?.email) {
//            return 
//         }

//     } catch (error) {
//         return
//     }
// }



// function generateTokens() {

// }
