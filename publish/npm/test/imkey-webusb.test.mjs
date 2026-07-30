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
