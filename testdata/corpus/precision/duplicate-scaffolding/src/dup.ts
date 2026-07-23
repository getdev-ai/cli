// two genuine near-duplicate helpers in ordinary src — SHOULD fire
export function computeTotal(items: { price: number; quantity: number }[]) {
  let total = 0;
  for (let i = 0; i < items.length; i++) {
    total += items[i].price * items[i].quantity;
  }
  return total;
}

export function sumOrders(orders: { price: number; quantity: number }[]) {
  let sum = 0;
  for (let j = 0; j < orders.length; j++) {
    sum += orders[j].price * orders[j].quantity;
  }
  return sum;
}

computeTotal([]);
sumOrders([]);
