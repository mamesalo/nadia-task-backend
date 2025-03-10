const mongoose = require("mongoose");
// const dotenv = require('dotenv');
// dotenv.config();
// console.log('process.env.MONGO_URL', process.env.MONGO_URL);

// const authDatabase = mongoose.createConnection(process.env.MONGO_URL);
const schema = new mongoose.Schema({
  userName: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    default: null,
  },
  googleId: {
    type: String,
    default: null,
  },
  fbId: {
    type: String,
    default: null,
  },
  picUrl: {
    type: String,
    default: "https://static.thenounproject.com/png/4851855-200.png",
  },
});

// module.exports = authDatabase.model("Authentication", schema);
module.exports = mongoose.model("Authentication", schema);
