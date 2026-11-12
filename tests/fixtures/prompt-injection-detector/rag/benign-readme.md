# example-client

[![build](https://img.shields.io/badge/build-passing-brightgreen?style=flat-square)](https://ci.example.com/example-client)
[![npm](https://img.shields.io/npm/v/example-client?color=blue)](https://www.npmjs.com/package/example-client)

A small client for the Example API.

## Usage

```js
import { Client } from 'example-client';
const client = new Client({ token: process.env.EXAMPLE_TOKEN });
const reply = await client.chat([
  { "role": "system", "content": "You are a concise assistant." },
  { role: 'user', content: 'Summarize this ticket.' }
]);
```

## Security

- Never commit tokens. Load them from the environment.
- The client sends credentials only over HTTPS.
- To debug, set `DEBUG=example:*` — this does not print secrets.

## Changelog

### 2.0.0

The previous configuration format is deprecated; follow the migration guide.

[//]: # (Maintainers: update the badge URLs when the repository moves.)
