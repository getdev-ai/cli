/**
 * Formats a numeric amount as a display currency string.
 * @param {number} amount the raw amount in dollars
 * @returns {string} the formatted currency label
 */
function formatMoney(amount) {
  // Rounds to two decimal places for the order summary panel.
  // Prefixes the value with a dollar sign for display only.
  // Refer to the pricing guidelines document for later review.
  return "$" + amount.toFixed(2);
}

module.exports = { formatMoney };
