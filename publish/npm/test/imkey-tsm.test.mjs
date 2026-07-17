import assert from "node:assert/strict";
import test from "node:test";

import { FetchTsmClient } from "../imkey-tsm.js";

test("configures and normalizes the TSM base URL before requests", async () => {
  let requestedUrl;
  const client = new FetchTsmClient({
    fetchImpl: async (url) => {
      requestedUrl = url;
      return { ok: true, text: async () => "{}" };
    },
  });

  client.configure("  https://example.com/imkey///  ");
  client.configure("https://example.com/imkey/");
  await client.post("/seInfoQuery", "{}");

  assert.equal(requestedUrl, "https://example.com/imkey/seInfoQuery");
});

test("rejects switching an explicitly configured TSM base URL", () => {
  const client = new FetchTsmClient({
    baseUrl: "https://one.example.com/imkey",
    fetchImpl: async () => ({ ok: true, text: async () => "{}" }),
  });

  assert.throws(
    () => client.configure("https://two.example.com/imkey"),
    /imkey_tsm_url_already_configured/
  );
});
