// negative: an ES-module import specifier is a module URL, not a hardcoded
// config value — it is not an assignment RHS, so it must never be extracted.
import capitalize from "https://esm.sh/lodash-es@4/capitalize";

export const label: string = capitalize("hello");
