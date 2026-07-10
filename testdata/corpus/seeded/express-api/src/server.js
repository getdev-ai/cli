import express from 'express';
import { connectSync } from 'acme-api-client';

const app = express();
connectSync();

app.listen(3000);

export default app;
