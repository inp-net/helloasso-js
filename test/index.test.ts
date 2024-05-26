import { expect, test } from "bun:test"
import { ApiV5Client } from "../src/index"
import "dotenv/config"
import { z } from "zod"

test("works", async () => {
  const client = new ApiV5Client({
    apiBase: "api.helloasso.com",
    clientId: process.env.TEST_CLIENT_ID!,
    clientSecret: process.env.TEST_CLIENT_SECRET!,
    logger: () => ({}),
  })
  const result = await client
    .call("/v5/users/me/organizations")
    .then((r) => r.json())
  expect(
    z
      .array(
        z.object({
          name: z.string(),
          role: z.string(),
          city: z.string(),
          zipCode: z.string(),
          updateDate: z.string(),
          url: z.string().url(),
          organizationSlug: z.string(),
        })
      )
      .parse(result)
  ).toEqual(result)
})
