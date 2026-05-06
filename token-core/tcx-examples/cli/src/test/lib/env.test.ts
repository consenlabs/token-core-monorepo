import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { getRuntimeEnv } from "../../lib/env";

// env.ts resolution order: process.env > import.meta.env
// Test environment is Node; import.meta.env is unavailable, so only process.env behaviour is verified.

const TEST_KEY = "VITE_TEST_ENV_VAR_XYZ";

describe("getRuntimeEnv", () => {
  beforeEach(() => {
    delete process.env[TEST_KEY];
  });

  afterEach(() => {
    delete process.env[TEST_KEY];
  });

  it("returns undefined when key is absent", () => {
    expect(getRuntimeEnv(TEST_KEY)).toBeUndefined();
  });

  it("returns value from process.env", () => {
    process.env[TEST_KEY] = "hello-world";
    expect(getRuntimeEnv(TEST_KEY)).toBe("hello-world");
  });

  it("trims whitespace from process.env value", () => {
    process.env[TEST_KEY] = "  trimmed  ";
    expect(getRuntimeEnv(TEST_KEY)).toBe("trimmed");
  });

  it("treats whitespace-only value as absent (returns undefined)", () => {
    process.env[TEST_KEY] = "   ";
    // empty after trim → falsy → falls through to import.meta.env (also absent) → undefined
    expect(getRuntimeEnv(TEST_KEY)).toBeUndefined();
  });
});
