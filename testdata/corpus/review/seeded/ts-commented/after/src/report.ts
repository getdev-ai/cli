export function buildReport(rows: string[]): string {
  // const header = computeHeader(rows);
  // if (header.length > 0) {
  //   rows.unshift(header);
  // }
  return rows.join("\n");
}
