// PREC-04: an object literal whose `key:` data field holds a taxonomy slug —
// a domain enum value, not a credential. The identifier name ("key") looks
// secret-ish, but the VALUE shape (a lowercase snake_case slug) is not.
export const category = {
  key: "yacht_management_guardianage",
  label: "Yacht Management",
};

export function categoryKey(): string {
  return category.key;
}
