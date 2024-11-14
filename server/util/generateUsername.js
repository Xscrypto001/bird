const User = require("../models/user");

const isUsernameTaken = async (username) => {
  const existingUser = await User.findOne({ username });
  return !!existingUser;
};
const generateUniqueUsername = async (fullname) => {
  const namesplit = fullname.split(" ");
  const firstName = namesplit[0];
  const lastName = namesplit[1];
  let baseUsername = `${firstName.toLowerCase()}${lastName.toLowerCase()}`;
  let username = baseUsername;

  let counter = 1;
  while (await isUsernameTaken(username)) {
    // If the username is already taken, modify it
    username = `${baseUsername}${counter}`;
    counter++;
  }

  return username;
};

module.exports = {
  generateUniqueUsername,
};
