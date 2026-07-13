const { formatUser } = require("./util");

const label = formatUser({ name: "ada" });
process.stdout.write(label);
