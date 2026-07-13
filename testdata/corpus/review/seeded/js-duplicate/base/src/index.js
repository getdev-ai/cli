const { sumList } = require("./helpers");

const total = sumList([1, 2, 3]);
process.stdout.write(String(total));
