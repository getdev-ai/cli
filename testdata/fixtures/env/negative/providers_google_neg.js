// must NOT fire: Google near-misses — wrong case prefix, and one char short
// of the minimum body length.
const googleKeyLowercasePrefix = "aizaFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK";
const googleKeyTooShort = "AIzaFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFA";
