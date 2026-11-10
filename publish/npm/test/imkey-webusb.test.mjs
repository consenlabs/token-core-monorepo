import assert from "node:assert/strict";
import test from "node:test";

import {
  encodeApduChunks,
  findAndClaimEndpoints,
  ImKeyWebUsbError,
  readApduResponse,
  WebUsbImKeyTransport,
} from "../imkey-webusb.js";

function packet(bytes) {
  const value = new Uint8Array(64);
  value.set(bytes);
  return { data: new DataView(value.buffer) };
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function usbHarness({ slowWrite = false, holdClose = false } = {}) {
  const endpoints = { interfaceNumber: 0, inEndpoint: 5, outEndpoint: 4, packetSize: 64 };
  const pendingReads = [];
  const pendingWrites = [];
  const closeStarted = deferred();
  const closeGate = deferred();
  const transferStarted = deferred();
  const events = [];
  const listeners = new Set();
  const device = {
    opened: true,
    vendorId: 0x096e,
    productId: 0x0891,
    serialNumber: "imkey-timeout",
    failClose: false,
    configuration: {
      interfaces: [{ interfaceNumber: 0, alternates: [{
        interfaceClass: 255,
        endpoints: [
          { direction: "in", endpointNumber: 5 },
          { direction: "out", endpointNumber: 4 },
        ],
      }] }],
    },
    async open() { events.push("open"); this.opened = true; },
    async claimInterface() { events.push("claim"); },
    async releaseInterface() { events.push("release"); },
    async close() {
      events.push("close:start");
      closeStarted.resolve();
      if (holdClose) await closeGate.promise;
      if (this.failClose) throw new Error("USB close failed");
      this.opened = false;
      for (const pending of [...pendingReads.splice(0), ...pendingWrites.splice(0)]) {
        pending.reject(new Error("Transfer cancelled by USB close"));
      }
      events.push("close:end");
    },
    async transferOut(_endpoint, data) {
      assert.equal(this.opened, true);
      events.push(`write:${data[7]}`);
      if (slowWrite) {
        const pending = deferred();
        pendingWrites.push(pending);
        transferStarted.resolve(pending);
        return pending.promise;
      }
    },
    async transferIn() {
      assert.equal(this.opened, true);
      events.push("read");
      const pending = deferred();
      pendingReads.push(pending);
      transferStarted.resolve(pending);
      return pending.promise;
    },
  };
  const api = {
    async getDevices() { events.push("devices"); return [device]; },
    addEventListener(_name, listener) { listeners.add(listener); },
    removeEventListener(_name, listener) { listeners.delete(listener); },
  };
  return {
    device, events, pendingReads, pendingWrites, closeStarted, closeGate, transferStarted,
    transport: new WebUsbImKeyTransport(device, endpoints, api),
    respond(status = 0x9000) {
      const pending = pendingReads.shift();
      assert.ok(pending, "a response must have exactly one waiting reader");
      assert.equal(pendingReads.length, 0);
      pending.resolve(packet([0, 0, 0, 0, 0xc3, 0, 2, status >> 8, status & 0xff]));
    },
    disconnect() {
      device.opened = false;
      for (const listener of listeners) listener({ device });
    },
  };
}

const hasCode = (code) => (error) => error instanceof ImKeyWebUsbError && error.code === code;
const nextTurn = () => new Promise((resolve) => setImmediate(resolve));

test("encodes first and continuation chunks with WebUSB framing", () => {
  const command = Array.from({ length: 80 }, (_, index) => index.toString(16).padStart(2, "0"))
    .join("");
  const chunks = encodeApduChunks(command);
  assert.equal(chunks.length, 2);
  assert.equal(chunks[0][4], 0xc3);
  assert.equal((chunks[0][5] << 8) | chunks[0][6], 80);
  assert.equal(chunks[1][4], 0);
  assert.deepEqual(Array.from(chunks[0].slice(7)), Array.from({ length: 57 }, (_, i) => i));
  assert.deepEqual(Array.from(chunks[1].slice(5, 28)), Array.from({ length: 23 }, (_, i) => i + 57));
});

test("discovers descriptor endpoints and prioritizes vendor-specific interface", async () => {
  const claimed = [];
  const device = {
    configuration: {
      interfaces: [
        { interfaceNumber: 0, alternates: [{ interfaceClass: 3, endpoints: [
          { direction: "in", endpointNumber: 5 }, { direction: "out", endpointNumber: 4 },
        ] }] },
        { interfaceNumber: 2, alternates: [{ interfaceClass: 255, endpoints: [
          { direction: "in", endpointNumber: 7 }, { direction: "out", endpointNumber: 6 },
        ] }] },
      ],
    },
    async claimInterface(value) { claimed.push(value); },
  };
  const endpoints = await findAndClaimEndpoints(device);
  assert.deepEqual(claimed, [2]);
  assert.deepEqual(endpoints, {
    interfaceNumber: 2,
    inEndpoint: 7,
    outEndpoint: 6,
    packetSize: 64,
  });
});

test("uses one deadline even when device keeps returning busy", async () => {
  const busy = packet([0, 0, 0, 0, 0xff]);
  const device = { async transferIn() { return busy; } };
  await assert.rejects(
    readApduResponse(device, 5, 5),
    (error) => error instanceof ImKeyWebUsbError && error.code === "webusb_apdu_timeout"
  );
});

test("serializes concurrent APDU exchanges", async () => {
  const events = [];
  const responses = [packet([0, 0, 0, 0, 0xc3, 0, 2, 0x90, 0x00]), packet([0, 0, 0, 0, 0xc3, 0, 2, 0x90, 0x00])];
  const device = {
    opened: true,
    async transferOut(_endpoint, data) { events.push(`write:${data[7]}`); },
    async transferIn() { events.push("read"); return responses.shift(); },
  };
  const transport = new WebUsbImKeyTransport(device, {
    interfaceNumber: 0, inEndpoint: 5, outEndpoint: 4, packetSize: 64,
  });
  await Promise.all([transport.sendApduRaw("01"), transport.sendApduRaw("02")]);
  assert.deepEqual(events, ["write:1", "read", "write:2", "read"]);
});

for (const slowWrite of [false, true]) {
  test(`${slowWrite ? "write" : "read"} timeout closes USB before queued retry and explicit reconnect`, async () => {
    const mock = usbHarness({ slowWrite, holdClose: true });
    const { transport } = mock;
    const timedOut = assert.rejects(transport.sendApduRaw("01", 20), hasCode("webusb_apdu_timeout"));
    const oldTransfer = await mock.transferStarted.promise;
    const retry = assert.rejects(transport.sendApduRaw("02"), hasCode("webusb_device_disconnected"));
    await mock.closeStarted.promise;
    assert.equal(transport.getDiagnostics().connected, false);
    const reconnect = transport.reconnect(100);
    await nextTurn();
    assert.deepEqual(mock.events, slowWrite ? ["write:1", "close:start"] : ["write:1", "read", "close:start"]);

    mock.closeGate.resolve();
    await Promise.all([timedOut, retry, reconnect]);
    assert.equal(mock.pendingReads.length, 0);
    assert.equal(mock.pendingWrites.length, 0);
    assert.ok(mock.events.indexOf("close:end") < mock.events.indexOf("open"));
    assert.equal(transport.getDiagnostics().connected, true);

    const response = transport.sendApduRaw("03");
    await nextTurn();
    // A late completion from the old transfer cannot consume the new response.
    oldTransfer.resolve(packet([0, 0, 0, 0, 0xc3, 0, 2, 0x6f, 0x00]));
    if (slowWrite) mock.pendingWrites.shift().resolve();
    await nextTurn();
    mock.respond();
    assert.equal(await response, "9000");
    assert.equal(mock.pendingReads.length, 0);
    await transport.close();
  });
}

test("automatic recovery after a slow response reconnects before retrying", async () => {
  const mock = usbHarness();
  const { transport } = mock;
  const recovery = (async () => {
    await assert.rejects(transport.sendApduRaw("01", 20), hasCode("webusb_apdu_timeout"));
    await assert.rejects(transport.sendApduRaw("02"), hasCode("webusb_device_disconnected"));
    await transport.reconnect(100);
    return transport.sendApduRaw("03");
  })();
  const oldRead = await mock.transferStarted.promise;
  await mock.closeStarted.promise;
  await nextTurn();
  oldRead.resolve(packet([0, 0, 0, 0, 0xc3, 0, 2, 0x6f, 0x00]));
  mock.respond();
  assert.equal(await recovery, "9000");
  assert.deepEqual(mock.events, [
    "write:1", "read", "close:start", "close:end", "devices", "open", "claim", "write:3", "read",
  ]);
  await transport.close();
});

test("failed timeout cleanup quarantines USB until close succeeds", async () => {
  const mock = usbHarness();
  mock.device.failClose = true;
  await assert.rejects(mock.transport.sendApduRaw("01", 10), hasCode("webusb_apdu_timeout"));
  await assert.rejects(mock.transport.sendApduRaw("02"), hasCode("webusb_device_disconnected"));
  await assert.rejects(mock.transport.reconnect(100), hasCode("webusb_device_disconnected"));
  assert.equal(mock.pendingReads.length, 1);
  assert.equal(mock.events.includes("devices"), false);
  mock.device.failClose = false;
  await mock.transport.reconnect(100);
  assert.equal(mock.pendingReads.length, 0);
  const response = mock.transport.sendApduRaw("03");
  await nextTurn();
  mock.respond();
  assert.equal(await response, "9000");
  await mock.transport.close();
});

test("all write chunks and the response share one APDU deadline", async (t) => {
  let now = 1_000;
  t.mock.method(Date, "now", () => now);
  for (const length of [80, 120]) {
    now = 1_000;
    const mock = usbHarness();
    let writes = 0;
    mock.device.transferOut = async () => { writes += 1; now += 10; };
    await assert.rejects(
      mock.transport.sendApduRaw("01".repeat(length), 20), hasCode("webusb_apdu_timeout")
    );
    assert.equal(writes, 2);
    assert.equal(mock.events.includes("read"), false);
    assert.equal(mock.device.opened, false);
    assert.equal(mock.transport.getDiagnostics().connected, false);
    await mock.transport.close();
  }
});

for (const [firmware, status] of [["COS", 0x905a], ["BLE", 0x9000]]) {
  test(`${firmware} restart still allows automatic reconnect after a successful APDU`, async () => {
    const mock = usbHarness();
    const response = mock.transport.sendApduRaw("01");
    await nextTurn();
    mock.respond(status);
    assert.equal(await response, status.toString(16).toUpperCase());
    mock.disconnect();
    await mock.transport.reconnect(100);
    const next = mock.transport.sendApduRaw("02");
    await nextTurn();
    mock.respond();
    assert.equal(await next, "9000");
    await mock.transport.close();
  });
}

test("reconnects the same authorized device and reclaims its endpoints", async () => {
  const endpoints = {
    interfaceNumber: 0, inEndpoint: 5, outEndpoint: 4, packetSize: 64,
  };
  const initial = {
    opened: true,
    vendorId: 0x096e,
    productId: 0x0891,
    serialNumber: "imkey-1",
    async releaseInterface() {},
    async close() { this.opened = false; },
  };
  const claimed = [];
  const replacement = {
    opened: false,
    vendorId: 0x096e,
    productId: 0x0891,
    serialNumber: "imkey-1",
    configuration: {
      interfaces: [{
        interfaceNumber: 2,
        alternates: [{
          interfaceClass: 255,
          endpoints: [
            { direction: "in", endpointNumber: 7 },
            { direction: "out", endpointNumber: 6 },
          ],
        }],
      }],
    },
    async open() { this.opened = true; },
    async claimInterface(value) { claimed.push(value); },
    async releaseInterface() {},
    async close() { this.opened = false; },
  };
  const listeners = new Set();
  const api = {
    async getDevices() { return [replacement]; },
    addEventListener(_name, listener) { listeners.add(listener); },
    removeEventListener(_name, listener) { listeners.delete(listener); },
  };
  const transport = new WebUsbImKeyTransport(initial, endpoints, api);
  transport.markDisconnected();

  await transport.reconnect(100);

  assert.equal(transport.device, replacement);
  assert.deepEqual(claimed, [2]);
  assert.equal(transport.getDiagnostics().connected, true);
  assert.deepEqual(transport.endpoints, {
    interfaceNumber: 2, inEndpoint: 7, outEndpoint: 6, packetSize: 64,
  });
  await transport.close();
  assert.equal(listeners.size, 0);
});
