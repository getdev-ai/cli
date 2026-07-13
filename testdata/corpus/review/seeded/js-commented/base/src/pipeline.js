function runPipeline(records) {
  const output = [];
  for (const record of records) {
    output.push(record.id);
  }
  return output;
}

module.exports = { runPipeline };
