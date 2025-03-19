const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const axios = require("axios");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const rateLimit = require("express-rate-limit");
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");
const zxcvbn = require("zxcvbn");
require("dotenv").config();

const { connectToDb } = require("./db/db.connect.js");

const User = require("./models/user.model.js");
const Post = require("./models/post.model.js");
const { timeStamp } = require("console");

const app = express();
const PORT = process.env.PORT || 4000;

const corsOptions = {
  origin: ["http://localhost:5173"],
  credentials: true,
  optionSuccessStatus: 200,
};

app.use(cors(corsOptions));
app.use(cookieParser());

if (!process.env.JWT_SECRET || !process.env.REFRESH_TOKEN_SECRET) {
  console.error(
    "CRITICAL ERROR: JWT secrets not set in environment variables!"
  );
  process.exit(1);
}

if (
  !process.env.EMAIL_HOST ||
  !process.env.EMAIL_PORT ||
  !process.env.EMAIL_USER ||
  !process.env.EMAIL_PASSWORD ||
  !process.env.EMAIL_FROM
) {
  console.warn(
    "WARNING: Email configuration not complete. Email features will not work."
  );
}

const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;

connectToDb();

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

const sendVerificationEmail = async (user, verificationUrl) => {
  try {
    await transporter.sendMail({
      from: `"${process.env.APP_NAME || "Auth System"}" <${
        process.env.EMAIL_FROM
      }>`,
      to: user.email,
      subject: "Verify Your Email Address",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Verify Your Email Address</h2>
          <p>Hi ${user.name},</p>
          <p>Thanks for registering! Please verify your email address by clicking the button below:</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${verificationUrl}" style="background-color: #4CAF50; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold;">Verify Email</a>
          </div>
          <p>This link will expire in 24 hours.</p>
          <p>If you didn't create an account, you can safely ignore this email.</p>
        </div>
      `,
    });
  } catch (error) {
    console.error("Error sending verification email:", error);
    throw new Error("Failed to send verification email");
  }
};

const sendPasswordResetEmail = async (user, resetUrl) => {
  try {
    await transporter.sendMail({
      from: `"${process.env.APP_NAME || "Auth System"}" <${
        process.env.EMAIL_FROM
      }>`,
      to: user.email,
      subject: "Password Reset Request",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Password Reset Request</h2>
          <p>Hi ${user.name},</p>
          <p>We received a request to reset your password. Click the button below to reset it:</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetUrl}" style="background-color: #4285F4; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold;">Reset Password</a>
          </div>
          <p>This link will expire in 1 hour.</p>
          <p>If you didn't request a password reset, you can safely ignore this email.</p>
        </div>
      `,
    });
  } catch (error) {
    console.error("Error sending password reset email:", error);
    throw new Error("Failed to send password reset email");
  }
};

const validatePassword = (password, userInfo = {}) => {
  if (password.length < 8) {
    return {
      valid: false,
      message: "Password must be at least 8 characters long",
      score: 0,
    };
  }

  const result = zxcvbn(password, [
    userInfo.email || "",
    userInfo.username || "",
    userInfo.name || "",
  ]);

  if (result.score < 2) {
    return {
      valid: false,
      message: result.feedback.warning || "Password is too weak",
      suggestions: result.feedback.suggestions,
      score: result.score,
    };
  }

  return {
    valid: true,
    score: result.score,
  };
};

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    message:
      "Too many login attempts from this IP, please try again after 15 minutes",
  },
});

const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    message: "Too many password reset attempts, please try again after an hour",
  },
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    message: "Too many requests, please try again later",
  },
});

app.use("/auth/login", loginLimiter);
app.use("/auth/forgot-password", passwordResetLimiter);
app.use("/api", apiLimiter);

const generateTokens = (user) => {
  const payload = {
    id: user._id,
    username: user.username || user.email,
  };

  const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: "15m" });

  const refreshToken = jwt.sign({ id: user._id }, REFRESH_TOKEN_SECRET, {
    expiresIn: "7d",
  });

  return { accessToken, refreshToken };
};

const setAuthCookies = (res, accessToken, refreshToken) => {
  res.cookie("access_token", accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 15 * 60 * 1000,
  });

  res.cookie("refresh_token", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/auth/refresh-token",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
};

const clearAuthCookies = (res) => {
  res.cookie("access_token", "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 0,
  });

  res.cookie("refresh_token", "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/auth/refresh-token",
    maxAge: 0,
  });
};

const authenticateToken = (req, res, next) => {
  const accessToken = req.cookies.access_token;

  if (!accessToken) {
    return res.status(401).json({ message: "Please log in to access." });
  }

  try {
    const decoded = jwt.verify(accessToken, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res
        .status(401)
        .json({ message: "Token expired", code: "TOKEN_EXPIRED" });
    }
    return res.status(403).json({ message: "Invalid token" });
  }
};

const requireVerifiedEmail = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (!user.emailVerified) {
      return res.status(403).json({
        message: "Please verify your email address to access this feature",
        code: "EMAIL_NOT_VERIFIED",
      });
    }

    next();
  } catch (error) {
    console.error("Email verification check error:", error);
    res.status(500).json({ message: "Server error" });
  }
};

app.post("/auth/register", async (req, res) => {
  const { username, name, email, password } = req.body;

  if (!username || !name || !email || !password) {
    return res
      .status(400)
      .json({ message: "Please provide all required fields" });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (email && !emailRegex.test(email)) {
    return res
      .status(400)
      .json({ message: "Please provide a valid email address" });
  }

  const passwordValidation = validatePassword(password, {
    username,
    email,
    name,
  });

  if (!passwordValidation.valid) {
    return res.status(400).json({
      message: passwordValidation.message,
      suggestions: passwordValidation.suggestions,
      score: passwordValidation.score,
    });
  }

  try {
    const existingUser = await User.findOne({
      $or: [{ username }, { email: email || null }],
    });

    if (existingUser) {
      res.status(400).json({
        message: existingUser.username
          ? "Username already exists"
          : "Email already exists",
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const emailVerificationToken = crypto.randomBytes(32).toString("hex");

    const newUser = new User({
      username,
      name,
      email: email || null,
      password: hashedPassword,
      emailVerified: false,
      emailVerificationToken,
      emailVerificationExpires: Date.now() + 24 * 60 * 60 * 1000,
    });

    await newUser.save();

    if (email) {
      const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${emailVerificationToken}`;
      await sendVerificationEmail(newUser, verificationUrl).catch((e) => {
        console.error("Failed to send verification email:", e);
      });
    }

    const { accessToken, refreshToken } = generateTokens(newUser);

    setAuthCookies(res, accessToken, refreshToken);

    const userResponse = {
      _id: newUser._id,
      name: newUser.name,
      username: newUser.username,
      email: newUser.email,
      emailVerified: newUser.emailVerified,
    };

    res.status(201).json({
      message: email
        ? "User registered successfully. Please check your email to verify your account."
        : "User registered successfully.",
      user: userResponse,
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({
      message: "Error registering user",
      error:
        process.env.NODE_ENV === "development" ? error.message : "Server error",
    });
  }
});

app.get("/auth/verify-email", async (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).json({ message: "Verification token is required" });
  }

  try {
    const user = await User.findOne({
      emailVerificationToken: token,
      emailVerificationExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({
        message: "Email verification token is invalid or has expired",
      });
    }

    user.emailVerified = true;
    user.emailVerificationExpires = undefined;
    user.emailVerificationToken = undefined;
    await user.save();

    res.redirect(`${process.env.FRONTEND_URL}/login?verified=true`);
  } catch (error) {
    console.error("Email verification error:", error);
    res.status(500).json({
      message: "Error verifying email",
      error:
        process.env.NODE_ENV === "development" ? error.message : "Server error",
    });
  }
});

app.post("/auth/resend-verification", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.emailVerified) {
      return res.status(400).json({ message: "Email is already verified" });
    }

    user.emailVerificationToken = crypto.randomBytes(32).toString("hex");
    user.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000;
    await user.save();

    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${user.emailVerificationToken}`;
    await sendVerificationEmail(user, verificationUrl);

    res.status(200).json({ message: "Verification email sent successfully" });
  } catch (error) {
    console.error("Error resending verification email:", error);
    res.status(500).json({ message: "Error sending verification email" });
  }
});

app.post("/auth/login", async (req, res) => {
  const { username, password, mfaToken } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Please provide username and password" });
  }

  try {
    const user = await User.findOne({
      $or: [{ username }, { email: username }],
    });

    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    if (!user.password) {
      return res.status(401).json({
        message:
          "This account uses social login. Please sign in with the appropriate provider.",
      });
    }

    const validatePassword = await bcrypt.compare(password, user.password);
    if (!validatePassword) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    if (user.mfaEnabled) {
      if (!mfaToken) {
        return res.status(200).json({
          message: "MFA required",
          requiresMfa: true,
          userId: user._id,
        });
      }

      const verified = speakeasy.totp.verify({
        secret: user.mfaSecret,
        encoding: "base32",
        token: mfaToken,
        window: 1,
      });

      if (!verified) {
        const backupCodeIndex = user.backupCodes?.findIndex(
          (bc) => bc.code === mfaToken && !bc.used
        );

        if (backupCodeIndex === -1) {
          return res.status(401).json({ message: "Invalid MFA Code" });
        }

        user.backupCodes[backupCodeIndex].used = true;
        await user.save();
      }
    }

    const { accessToken, refreshToken } = generateTokens(user);

    setAuthCookies(res, accessToken, refreshToken);

    const userResponse = {
      _id: user._id,
      username: user.username,
      name: user.name,
      email: user.email,
      avatar: user.avatar,
      emailVerified: user.emailVerified,
      mfaEnabled: user.mfaEnabled,
    };

    res.status(200).json({
      message: "Logged in successfully",
      user: userResponse,
    });
  } catch (error) {
    res.status(500).json({
      message: "Error logging in",
      error:
        process.env.NODE_ENV === "development" ? error.message : "Server error",
    });
  }
});

app.post("/auth/forgot-password", passwordResetLimiter, async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Email is required" });
  }

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(200).json({
        message:
          "If a user with that email exists, a password reset link has been sent.",
      });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");

    user.resetPasswordToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .toString("hex");
    user.resetPasswordExpires = Date.now() + 60 * 60 * 1000; // Fixed the plus sign issue
    await user.save();

    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;
    await sendPasswordResetEmail(user, resetUrl);

    res.status(200).json({
      message:
        "If a user with that email exists, a password reset link has been sent.",
    });
  } catch (error) {
    console.error("Password reset request error:", error);
    res.status(500).json({
      message: "Error processing password reset request",
      error:
        process.env.NODE_ENV === "development" ? error.message : "Server error",
    });
  }
});

app.post("/auth/reset-password", async (req, res) => {
  const { token, password } = req.body;

  if (!token || !password) {
    return res.status(400).json({ message: "Token and password are required" });
  }

  const passwordValidation = validatePassword(password);

  if (!passwordValidation.valid) {
    return res.status(400).json({
      message: passwordValidation.message,
      suggestions: passwordValidation.suggestions,
      score: passwordValidation.score,
    });
  }

  try {
    const hashedToken = crypto
      .createHash("sha256")
      .update(token)
      .toString("hex");

    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({
        message: "Password reset token is invalid or has expired",
      });
    }

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    const { accessToken, refreshToken } = generateTokens(user);
    setAuthCookies(res, accessToken, refreshToken);

    res.status(200).json({
      message: "Password has been reset successfully",
    });
  } catch (error) {
    console.error("Password reset error:", error);
    res.status(500).json({
      message: "Error resetting password",
      error:
        process.env.NODE_ENV === "development" ? error.message : "Server error",
    });
  }
});

app.post("/auth/mfa/setup", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const secret = speakeasy.generateSecret({
      name: `${process.env.APP_NAME || "Auth System"}:${
        user.email || user.username
      }`,
    });

    user.mfaSecret = secret.base32;
    await user.save();

    const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);

    res.status(200).json({
      secret: secret.base32,
      qrCode: qrCodeUrl,
    });
  } catch (error) {
    console.error("MFA setup error:", error);
    res.status(500).json({
      message: "Error setting up MFA",
      error:
        process.env.NODE_ENV === "development" ? error.message : "Server error",
    });
  }
});

app.post("/auth/mfa/verify", authenticateToken, async (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ message: "Verification token is required" });
  }

  try {
    const user = await User.findById(req.user.id);

    if (!user || !user.mfaSecret) {
      return res.status(400).json({ message: "MFA setup not initiated" });
    }

    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: "base32",
      token,
      window: 1,
    });

    if (!verified) {
      return res.status(400).json({ message: "Invalid verification code" });
    }

    user.mfaEnabled = true;

    const backupCodes = [];

    for (let i = 0; i < 10; i++) {
      const code = crypto.randomBytes(4).toString("hex").toUpperCase();
      backupCodes.push({
        code,
        used: false,
      });
    }

    user.backupCodes = backupCodes;

    await user.save();

    res.status(200).json({
      message: "MFA enabled successfully",
      backupCodes: backupCodes.map((bc) => bc.code),
    });
  } catch (error) {
    console.error("MFA verification error:", error);
    res.status(500).json({
      message: "Error verifying MFA",
      error:
        process.env.NODE_ENV === "development" ? error.message : "Server error",
    });
  }
});

app.post("/auth/mfa/disable", authenticateToken, async (req, res) => {
  const { password, mfaToken } = req.body;

  if (!password) {
    return res.status(400).json({ message: "Password is required" });
  }

  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (!user.mfaEnabled) {
      return res.status(400).json({ message: "MFA is not enabled" });
    }

    const validatePassword = await bcrypt.compare(password, user.password);
    if (!validatePassword) {
      return res.status(401).json({ message: "Invalid password" });
    }

    if (user.mfaEnabled) {
      if (!mfaToken) {
        return res.status(400).json({ message: "MFA token is required" });
      }

      const verified = speakeasy.totp.verify({
        secret: user.mfaSecret,
        encoding: "base32",
        token: mfaToken,
        window: 1,
      });

      if (!verified) {
        const backupCodeIndex = user.backupCodes.findIndex(
          (bc) => bc.code === mfaToken && !bc.used
        );

        if (backupCodeIndex === -1) {
          return res.status(401).json({ message: "Invalid MFA code" });
        }
      }
    }

    user.mfaEnabled = false;
    user.mfaSecret = undefined;
    user.backupCodes = undefined;
    await user.save();

    res.status(200).json({ message: "MFA disabled successfully" });
  } catch (error) {
    console.error("MFA disable error:", error);
    res.status(500).json({
      message: "Error disabling MFA",
      error:
        process.env.NODE_ENV === "development" ? error.message : "Server error",
    });
  }
});

app.post("/auth/refresh-token", async (req, res) => {
  const refreshToken = req.cookies.refresh_token;

  if (!refreshToken) {
    return res.status(401).json({ message: "No refresh token provided" });
  }

  try {
    const decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
    
    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    const tokens = generateTokens(user);

    setAuthCookies(res, tokens.accessToken, tokens.refreshToken);

    res.status(200).json({ message: "Token refreshed successfully" });
  } catch (error) {
    clearAuthCookies(res);

    if (error.name === "TokenExpiredError") {
      return res
        .status(401)
        .json({ message: "Refresh token expired, please login again" });
    }

    return res.status(403).json({ message: "Invalid refresh token" });
  }
});

app.get("/auth/me", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select(
      "-password -__v -resetPasswordToken -resetPasswordExpires -mfaSecret -backupCodes"
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(user);
  } catch (error) {
    console.error("Error fetching user profile:", error);
    res.status(500).json({
      message: "Error fetching profile",
      error:
        process.env.NODE_ENV === "development" ? error.message : "Server error",
    });
  }
});

app.post("/auth/logout", (req, res) => {
  clearAuthCookies(res);
  res.status(200).json({ message: "Logged out successfully" });
});

const generateOAuthState = () => {
  return crypto.randomBytes(32).toString("hex");
};

const oauthStates = new Map();

app.get("/auth/google", (req, res) => {
  const state = generateOAuthState();
  oauthStates.set(state, { timestamp: Date.now() });

  const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  authUrl.searchParams.append("client_id", process.env.GOOGLE_CLIENT_ID);
  authUrl.searchParams.append(
    "redirect_uri",
    `${process.env.API_URL}/auth/google/callback`
  );
  authUrl.searchParams.append("response_type", "code");
  authUrl.searchParams.append("scope", "profile email");
  authUrl.searchParams.append("state", state);

  res.redirect(authUrl.toString());
});

app.get("/auth/google/callback", async (req, res) => {
  const { code, state } = req.query;

  if (!state || !oauthStates.has(state)) {
    return res.redirect(`${process.env.FRONTEND_URL}/auth?error=invalid_state`);
  }

  oauthStates.delete(state);

  if (!code) {
    return res.redirect(
      `${process.env.FRONTEND_URL}/auth?error=google_auth_failed`
    );
  }

  try {
    const tokenResponse = await axios.post(
      "https://oauth2.googleapis.com/token",
      {
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: `${process.env.API_URL}/auth/google/callback`,
        grant_type: "authorization_code",
      }
    );

    const { access_token } = tokenResponse.data;

    const userInfoResponse = await axios.get(
      "https://www.googleapis.com/oauth2/v2/userinfo",
      { headers: { Authorization: `Bearer ${access_token}` } }
    );

    const googleUserInfo = userInfoResponse.data;

    let user = await User.findOne({ googleId: googleUserInfo.id });

    if (!user) {
      if (googleUserInfo.email) {
        const existingUser = await User.findOne({
          email: googleUserInfo.email,
        });

        if (existingUser) {
          existingUser.googleId = googleUserInfo.id;
          existingUser.avatar = existingUser.avatar || googleUserInfo.picture;
          existingUser.emailVerified = true;
          user = await existingUser.save();
        }
      }

      if (!user) {
        user = new User({
          googleId: googleUserInfo.id,
          name: googleUserInfo.name,
          email: googleUserInfo.email,
          username: googleUserInfo.email
            ? googleUserInfo.email.split("@")[0]
            : `user_${googleUserInfo.id}`,
          avatar: googleUserInfo.picture,
          emailVerified: true,
        });

        await user.save();
      }
    }

    const { accessToken, refreshToken } = generateTokens(user);
    setAuthCookies(res, accessToken, refreshToken);

    const userForFrontend = {
      _id: user._id,
      username: user.username,
      name: user.name,
      email: user.email,
      avatar: user.avatar,
      googleId: user.googleId,
      emailVerified: user.emailVerified,
    };

    res.redirect(
      `${process.env.FRONTEND_URL}/auth/success?user=${encodeURIComponent(
        JSON.stringify(userForFrontend)
      )}&provider=google`
    );
  } catch (error) {
    console.error("Google auth error:", error);
    res.redirect(`${process.env.FRONTEND_URL}/auth?error=google_auth_failed`);
  }
});

app.get("/auth/github", (req, res) => {
  const state = generateOAuthState();
  oauthStates.set(state, { timestamp: Date.now() });

  const authUrl = new URL("https://github.com/login/oauth/authorize");
  authUrl.searchParams.append("client_id", process.env.GITHUB_CLIENT_ID);
  authUrl.searchParams.append(
    "redirect_uri",
    `${process.env.API_URL}/auth/github/callback`
  );
  authUrl.searchParams.append("scope", "user:email");
  authUrl.searchParams.append("state", state);

  res.redirect(authUrl.toString());
});

app.get("/auth/github/callback", async (req, res) => {
  const { code, state } = req.query;

  if (!state || !oauthStates.has(state)) {
    return res.redirect(`${process.env.FRONTEND_URL}/auth?error=invalid_state`);
  }

  oauthStates.delete(state);

  if (!code) {
    return res.redirect(
      `${process.env.FRONTEND_URL}/auth?error=github_auth_failed`
    );
  }

  try {
    const tokenResponse = await axios.post(
      "https://github.com/login/oauth/access_token",
      {
        client_id: process.env.GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: `${process.env.API_URL}/auth/github/callback`,
      },
      {
        headers: { Accept: "application/json" },
      }
    );

    const { access_token } = tokenResponse.data;

    const userResponse = await axios.get("https://api.github.com/user", {
      headers: { Authorization: `token ${access_token}` },
    });

    const githubUserInfo = userResponse.data;

    let email = githubUserInfo.email;

    if (!email) {
      try {
        const emailResponse = await axios.get(
          "https://api.github.com/user/emails",
          {
            headers: { Authorization: `token ${access_token}` },
          }
        );

        const primaryEmail = emailResponse.data.find((e) => e.primary);
        if (primaryEmail) {
          email = primaryEmail.email;
        } else if (emailResponse.data.length > 0) {
          email = emailResponse.data[0].email;
        }
      } catch (error) {
        console.error("Error fetching GitHub emails:", error);
      }
    }

    let user = await User.findOne({ githubId: githubUserInfo.id });

    if (!user) {
      if (email) {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
          existingUser.githubId = githubUserInfo.id;
          existingUser.avatar =
            existingUser.avatar || githubUserInfo.avatar_url;
          existingUser.emailVerified = true;
          user = await existingUser.save();
        }
      }

      if (!user) {
        user = new User({
          githubId: githubUserInfo.id,
          name: githubUserInfo.name || githubUserInfo.login,
          email: email,
          username:
            githubUserInfo.login ||
            (email ? email.split("@")[0] : `user_${githubUserInfo.id}`),
          avatar: githubUserInfo.avatar_url,
          // For OAuth users, mark email as verified
          emailVerified: true,
        });

        await user.save();
      }
    }

    const { accessToken, refreshToken } = generateTokens(user);
    setAuthCookies(res, accessToken, refreshToken);

    const userForFrontend = {
      _id: user._id,
      username: user.username,
      name: user.name,
      email: user.email,
      avatar: user.avatar,
      githubId: user.githubId,
      emailVerified: user.emailVerified,
    };

    res.redirect(
      `${process.env.FRONTEND_URL}/auth/success?user=${encodeURIComponent(
        JSON.stringify(userForFrontend)
      )}&provider=github`
    );
  } catch (error) {
    console.error("GitHub auth error:", error);
    res.redirect(`${process.env.FRONTEND_URL}/auth?error=github_auth_failed`);
  }
});

//CRUD

app.use((req, res, next) => {
  res.status(404).json({ message: "Resource not found" });
});

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({
    message: "Internal server error",
    error: process.env.NODE_ENV === "development" ? err.message : null,
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || "development"}`);
});