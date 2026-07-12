// seeded defect: VITE_ prefix inlines this Google API key into the client
// bundle (value is fake)
const VITE_GOOGLE_MAPS_KEY: string = "AIzaFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFA1";

export function mapsUrl(): string {
  return `https://maps.googleapis.com/maps/api/js?key=${VITE_GOOGLE_MAPS_KEY}`;
}
