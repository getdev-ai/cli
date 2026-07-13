function runPipeline(records) {
  const output = [];
  console.log("running pipeline", records.length);
  // const legacy = buildLegacyIndex(records);
  // for (let i = 0; i < legacy.length; i++) {
  //   output.push(legacy[i].id);
  // }
  for (const record of records) {
    output.push(record.id);
  }
  return output;
}

module.exports = { runPipeline };
