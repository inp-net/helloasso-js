# helloasso

Largely converted from the [official Python wrapper](https://github.com/HelloAsso/HaApiV5) to TypeScript.

## Installation

```bash
npm install helloasso
```

## Usage

```typescript
import { ApiV5Client as HelloAsso } from "helloasso"

const helloAsso = new HelloAsso({
  apiBase: "api.helloasso.com",
  clientId: "your-client-id",
  clientSecret: "your-client",
})

const response = await helloAsso.call("/v5/users/me/organizations")
console.log(await response.json())
```

## Development

This package is developed using [Bun](https://bun.sh).
