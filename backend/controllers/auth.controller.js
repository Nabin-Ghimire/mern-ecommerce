import { populate } from "dotenv";
import { redis } from "../lib/redis.js";
import User from "../models/user.model.js";
import jwt from "jsonwebtoken";
const generateTokens = (userId) => {
  const accessToken = jwt.sign({ userId }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" });
  const refreshToken = jwt.sign({ userId }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "7d" });
  return { accessToken, refreshToken };
}
const storeRefreashToken = async (userId, refreshToken) => {
  await redis.set(`refresh_token:${userId}`, refreshToken, 'EX', 60 * 60 * 24 * 7) // 7 days`,)
}

const setCookies = (res, accessToken, refreshToken) => {
  res.cookie("accessToken", accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 15 * 60 * 1000
  })
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000
  })
}

export const signup = async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const userExists = await User.findOne({
      email
    })
    if (userExists) {
      return res.status(400).json({
        message: "User already exists"
      })
    }

    const user = await User.create({ name, email, password })

    const { accessToken, refreshToken } = generateTokens(user._id);

    await storeRefreashToken(user._id, refreshToken);
    setCookies(res, accessToken, refreshToken)

    res.status(201).json({

      _id: user._id,
      name: user.name,
      email: user.email,
      role: user.role

    });
  } catch (error) {
    res.status(500).json({ message: error.message })
  }


}

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user && (await user.comparePassword(password))) {
      const { accessToken, refreshToken } = generateTokens(user._id);
      await storeRefreashToken(user._id, refreshToken);
      setCookies(res, accessToken, refreshToken)
      res.status(200).json({

        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role

      })
    }
    else {
      res.status(400).json({ message: "Invalid email or password" });
    }

  } catch (error) {
    console.log("Error in login controller", error.message);
    res.status(500).json({ message: error.message });
  }
}

export const logout = async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (refreshToken) {
      const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
      await redis.del(`refresh_token:${decoded.userId}`);
    }
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    res.json({
      message: "Logged out successfully"
    })
  } catch (error) {
    console.log("Error in logout controller", error.message);
    res.status(500).json({ message: "server error", error: error.message });
  }
}

export const refreshToken = async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
      return res.status(401).json({ message: "Refresh token not found" })
    }

    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const storedToken = await redis.get(`refresh_token:${decoded.userId}`);
    if (storedToken !== refreshToken) {
      return res.status(401).json({ message: "Invalid refresh token" });
    }
    const accessToken = jwt.sign({ userId: decoded.userId }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" });
    res.cookie("accessToken", accessToken, { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict", maxAge: 15 * 60 * 1000 });
    res.json({ message: "Token refreshed successfully", accessToken });
  } catch (error) {
    console.log("Error in refresh Token controller", error.message);
    res.status(500).json({ message: "server error", error: error.message, });
  }
}

export const getProfile = (req, res) => {
  try {
    res.json(req.user);
  } catch (error) {
    console.log("Error in getProfile controller", error.message);
    res.status(500).json({ message: "server error", error: error.message });
  }
}