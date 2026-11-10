import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, copyFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { runDeviceSession } from "../imkey-session.js";

test("device session serializes clients even across wasm runtimes", async () => {
  const transport = {};
  const log = [];
  await Promise.all([{}, {}].map((runtime, index) => runDeviceSession(transport, runtime, async () => {
    log.push(`start${index}`);
    await new Promise((resolve) => setTimeout(resolve, 5));
    log.push(`end${index}`);
  })));
  assert.deepEqual(log, ["start0", "end0", "start1", "end1"]);
});

test("public signTx and getSeid stay atomic across clients and recover from failure", async () => {
  const directory = await mkdtemp(join(tmpdir(), "imkey-session-"));
  try {
    for (const file of ["imkey-core.js", "imkey-session.js", "imkey-webusb.js", "imkey-storage.js", "imkey-tsm.js"])
      await copyFile(new URL(`../${file}`, import.meta.url), join(directory, file));
    await writeFile(join(directory, "package.json"), '{"type":"module"}');
    await writeFile(join(directory, "ikc_wasm.js"), `
      export default async function init() {}
      let transport, tsm, storage;
      export function set_transport(value) { transport = value; }
      export function set_transport_profile() {}
      export function set_tsm_client(value) { tsm = value; }
      export function set_binding_storage(value) { storage = value; }
      export async function sign_tx(input) {
        const params = JSON.parse(input);
        await transport.sendApduRaw("SELECT_SIGN");
        await transport.sendApduRaw("PREPARE");
        if (params.fail) throw new Error("mock_sign_failure");
        await transport.sendApduRaw("SIGN");
        return JSON.stringify({ signature: "signed", owner: tsm.owner, storage: storage.owner });
      }
      export async function get_seid() {
        await transport.sendApduRaw("SELECT_ISD");
        return transport.sendApduRaw("SEID");
      }
    `);
    const { ImKeyCore } = await import(pathToFileURL(join(directory, "imkey-core.js")));
    const log = [];
    let selected;
    const transport = { async sendApduRaw(apdu) {
      log.push(apdu);
      await new Promise((resolve) => setTimeout(resolve, 1));
      if (apdu.startsWith("SELECT")) selected = apdu;
      if (["PREPARE", "SIGN"].includes(apdu)) assert.equal(selected, "SELECT_SIGN");
      if (apdu === "SEID") { assert.equal(selected, "SELECT_ISD"); return "seid"; }
      return "9000";
    } };
    const clients = ["first", "second"].map((owner) => {
      const client = new ImKeyCore({ tsmClient: { owner }, storage: { owner } });
      client.session = { transport, async disconnect() { log.push("CLOSE"); } };
      return client;
    });
    const result = await Promise.all([clients[0].signTx({}), clients[1].getSeid(), clients[1].signTx({})]);
    assert.deepEqual(result, [{ signature: "signed", owner: "first", storage: "first" }, "seid", { signature: "signed", owner: "second", storage: "second" }]);
    assert.deepEqual(log, ["SELECT_SIGN", "PREPARE", "SIGN", "SELECT_ISD", "SEID", "SELECT_SIGN", "PREPARE", "SIGN"]);
    log.length = 0;
    const failed = await Promise.allSettled([clients[0].signTx({ fail: true }), clients[1].getSeid()]);
    assert.match(failed[0].reason.message, /mock_sign_failure/);
    assert.equal(failed[1].value, "seid");
    assert.deepEqual(log, ["SELECT_SIGN", "PREPARE", "SELECT_ISD", "SEID"]);
    await clients[0].disconnect();
    assert.equal(await clients[1].getSeid(), "seid");
    await assert.rejects(clients[0].getSeid(), /imkey_transport_not_set/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
