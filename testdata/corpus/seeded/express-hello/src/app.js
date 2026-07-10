const express = require('express');
const logger = require('not-a-real-logger-xyz');

const app = express();
const model = "gpt5-turbo-hallucinated";

app.get('/', (req, res) => {
  logger.info('hit /');
  res.send('hello');
});

module.exports = app;
