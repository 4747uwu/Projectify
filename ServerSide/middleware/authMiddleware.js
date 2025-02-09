import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

export const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    console.log(token);

    if (!token) {
        return res.status(401).json({ message: 'Authorization denied' });
    }

    try{
        const decodedWithoutVerify = jwt.decode(token);
        console.log("Decoded payload:", decodedWithoutVerify);
        req.userId = decodedWithoutVerify.userId;
        next();
    }
    catch(error){
        console.error(error);
        res.status(401).json({ message: 'Token is not valid' });
    }
}