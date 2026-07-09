function greet(name) {
  return `hello ${name}`;
}

const add = (a, b) => a + b;

class Cart {
  total() {
    return this.items.reduce((sum, i) => sum + i.price, 0);
  }
}
