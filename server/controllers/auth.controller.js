const { validationResult } = require("express-validator");
const bcrypt = require("bcrypt");
const User = require("../models/user");
const HttpError = require("../models/http-error");
const {
  generateAuthTokens,
  verifyToken,
  InvalidTokenError,
  generateResetToken,
} = require("../util/token");
const {
  generatePasswordResetPayload,
  sendMail,
  EmailType,
} = require("../services/sendgrid");
const { generateUniqueUsername } = require("../util/generateUsername");

const AUTHORIZATION_HEADER_NAME = "Authorization";
const REFRESH_TOKEN_HEADER_NAME = "Refresh-Token";

const ACCESS_LEVELS = {
  ADMIN: 0,
  USER: 1,
  GUEST: 2,
};

const addAuthorization = (res, tokenBody) => {
  const { refreshToken, accessToken } = generateAuthTokens(tokenBody);
  res.setHeader(AUTHORIZATION_HEADER_NAME, `Bearer ${accessToken}`);
  res.setHeader(REFRESH_TOKEN_HEADER_NAME, refreshToken);
};

const signup = async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(new HttpError("Invalid input passed", 422));
  }

  const { fullName, email, password } = req.body;

  const existingUser = await User.findOne({ email });

  if (existingUser) {
    const error = new HttpError("User already exists", 422);
    return next(error);
  }

  let hashedPassword;
  try {
    hashedPassword = await bcrypt.hash(password, 12);
  } catch (err) {
    const error = new HttpError("Failed to create user", 500);
    return next(error);
  }

  const defaultUsername = await generateUniqueUsername(fullName);

  let newUser = new User({
    name: fullName,
    email: email,
    contact: null,
    username: defaultUsername,
    password: hashedPassword,
    places: [],
    bookmarks: [],
    verificationDetails: {
      website: null,
      document: null,
      officialEmail: null,
      newsArticles: [],
      googleTrendsProfile: null,
      wikipediaLink: null,
      instagramLink: null,
    },
    verified: false,
    followers: [],
    following: [],
    lastLogin: new Date(),
    customerId: null,
    planId: null,
    subscriptionId: null,
    paymentMethods: [],
    mutedUsers: [],
    blockedUsers: [],
    reportedUsers: [],
    accessRight: ACCESS_LEVELS.USER,
  });

  try {
    newUser = await newUser.save();
  } catch (err) {
    const error = new HttpError(
      "Signing up failed, please try again later." + err,
      500
    );
    return next(error);
  }

  addAuthorization(res, { userId: newUser._id.toHexString() });

  return res.status(201).json(newUser);
};

const signin = async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(new HttpError("Invalid input passed", 422));
  }

  const { email, password } = req.body;

  let user;
  try {
    user = await User.findOne({ email });
    if (!user) {
      const error = new HttpError(
        "Invalid credentials, could not log you in.",
        403
      );
      return next(error);
    }
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      const error = new HttpError(
        "Invalid credentials, could not log you in.",
        403
      );
      return next(error);
    }
    addAuthorization(res, { userId: user._id.toHexString() });
    console.log("User logged in");
    return res.status(200).send(user);
  } catch (e) {
    const error = new HttpError(
      "Logging in failed, please try again later.",
      500
    );
    return next(error);
  }
};

const handleRefreshToken = async (req, res) => {
  try {
    const oldRefreshToken = req.header(REFRESH_TOKEN_HEADER_NAME);
    const decodedToken = verifyToken(oldRefreshToken);

    addAuthorization(res, { userId: decodedToken.userId });

    return res.status(200).send({ userId: decodedToken.userId });
  } catch (e) {
    if (e instanceof Error) {
      console.error("HandleRefreshToken:", e.message);
    }
    if (e instanceof InvalidTokenError) {
      return res
        .status(401)
        .send({ message: "The refresh token provided was invalid" });
    } else {
      return res.status(500).send({
        message: "An error ocurred while trying to refresh the access token",
      });
    }
  }
};

const handleForgetPassword = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty) {
      return res.status(400).send({ message: "invalid input passed" });
    }
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      console.error("HandleForgetPassword: email not found");
      return res
        .status(404)
        .send({ message: "The email provided does not have an account" });
    }
    const resetToken = generateResetToken({ userId: user._id.toHexString() });

    const payload = generatePasswordResetPayload(
      resetToken,
      user.name.split(" ")[0]
    );

    await sendMail(EmailType.PasswordReset, {
      to: email,
      dynamicTemplateData: payload,
    });

    return res.status(200).send({ message: "Reset Password mail sent" });
  } catch (e) {
    return res.status(500).send({ message: "Token has expired" });
  }
};

const handleResetPassword = async (req, res) => {
  try {
    const token = req.params.token;
    const { password } = req.body;

    const decodedToken = verifyToken(token);
    const user = await User.findById(decodedToken.userId);

    if (!user) {
      return res.status(404).send({ message: "could not find user" });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    user.password = hashedPassword;

    await user.save();
    res.status(200).send({ message: "Password reset successful" });
  } catch (err) {
    console.log("reset password error", err);
    return res.status(401).send({ message: "Token has expired" });
  }
};

module.exports = {
  addAuthorization,
  signup,
  signin,
  handleRefreshToken,
  handleForgetPassword,
  handleResetPassword,
};
