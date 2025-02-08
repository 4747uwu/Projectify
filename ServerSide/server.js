import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import http from "http";
import connectDB from "./config/db.js";

const PORT=4000;
const app = express();
app.use(cors());
app.use(cookieParser());
connectDB();

app.get("/", (req, res) => {
    res.send("Hello World");
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

// server.listen(PORT, () => {
//   console.log(`Server is running on port ${PORT}`);
// });