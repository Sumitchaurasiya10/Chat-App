import jwt from "jsonwebtoken";
import User from "../models/user.model.js";

export const protectRoute = async (req, res, next) => {
    try {
        // Get token from cookies
        const token = req.cookies?.jwt; 

        if (!token) {
            return res.status(401).json({ message: "Unauthorized - No token provided" });
        }

        // Verify token
        let decoded;
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET);
        } catch (error) {
            console.log("JWT Error:", error.message);
            return res.status(401).json({ message: "Unauthorized - Invalid or expired token" });
        }

        // Ensure decoded payload contains userId
        if (!decoded?.userId) {
            return res.status(401).json({ message: "Unauthorized - Invalid token structure" });
        }

        // Fetch user from database
        const user = await User.findById(decoded.userId).select("-password");
        if (!user) {
            return res.status(401).json({ message: "Unauthorized - User not found" });
        }

        // Attach user to request object
        req.user = user;
        next();
    } catch (error) {
        console.log("Error in protectRoute middleware:", error.message);
        return res.status(500).json({ message: "Internal Server Error" });
    }
};
