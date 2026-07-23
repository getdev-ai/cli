// PREC-04: an uploaded-file object key (an S3-style filename) assigned to a
// secret-suggesting name (cvFileKey) — a filename with an extension, not a
// credential. The VALUE shape (a path/filename ending in .pdf) is rejected by
// the value-shape gate regardless of the identifier name.
const cvFileKey = "crew-3f9a1c02-d7b4-8e65.pdf";
const avatarKey = "uploads/user-abc123def456.jpg";

export { cvFileKey, avatarKey };
