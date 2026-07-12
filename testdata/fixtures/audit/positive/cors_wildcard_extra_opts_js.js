const cors = require("cors");

const corsOptions = cors({
  credentials: true,
  origin: "*",
  methods: ["GET", "POST"],
});

module.exports = corsOptions;
