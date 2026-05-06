import { describe, expect, it } from "vitest";

import { retry, withTimeout } from "../../lib/resilience";

describe("resilience helpers", () => {
  it("withTimeout returns result before timeout", async () => {
    const result = await withTimeout(async () => "ok", 100, "timeout");
    expect(result).toBe("ok");
  });

  it("withTimeout throws when exceeded", async () => {
    await expect(
      withTimeout(
        () =>
          new Promise((resolve) => {
            setTimeout(() => resolve("late"), 30);
          }),
        5,
        "timeout",
      ),
    ).rejects.toThrow("timeout");
  });

  it("retry succeeds on second attempt", async () => {
    let attempt = 0;
    const result = await retry(async () => {
      attempt += 1;
      if (attempt === 1) throw new Error("first failed");
      return "ok";
    });

    expect(result).toBe("ok");
    expect(attempt).toBe(2);
  });
});
