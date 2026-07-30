const PACKET_SIZE = 64;
const FIRST_DATA_OFFSET = 7;
const NEXT_DATA_OFFSET = 5;
const FIRST_MAX_PAYLOAD = PACKET_SIZE - FIRST_DATA_OFFSET;
const NEXT_MAX_PAYLOAD = PACKET_SIZE - NEXT_DATA_OFFSET;
const CMD_MESSAGE = 0xc3;
const BUSY_INDICATOR = 0xff;
const DEFAULT_TIMEOUT_MS = 20_000;

export class ImKeyWebUsbError extends Error {
  constructor(message, code) {
    super(message);
    this.name = "ImKeyWebUsbError";
    this.code = code;
  }
}

function usb() {
  const api = globalThis.navigator?.usb;
  if (!api) {
    throw new ImKeyWebUsbError(
      "WebUSB is not supported. Please use Chrome or Edge.",
      "webusb_unsupported"
    );
  }
  return api;
}

export function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

export function hexToBytes(value) {
  const normalized = value.trim().replace(/^0x/i, "");
  if (normalized.length % 2 !== 0 || /[^a-fA-F0-9]/.test(normalized)) {
    throw new ImKeyWebUsbError("Invalid APDU hex string.", "invalid_apdu_hex");
  }
  const bytes = new Uint8Array(normalized.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

export function encodeApduChunks(apduHex) {
  const command = hexToBytes(apduHex);
  const chunks = [];
  let offset = 0;

  const firstSize = Math.min(FIRST_MAX_PAYLOAD, command.length);
  const first = new Uint8Array(PACKET_SIZE);
  first[4] = CMD_MESSAGE;
  first[5] = (command.length >> 8) & 0xff;
  first[6] = command.length & 0xff;
  first.set(command.subarray(0, firstSize), FIRST_DATA_OFFSET);
  chunks.push(first);
  offset += firstSize;

  let sequence = 0;
  while (offset < command.length) {
    const size = Math.min(NEXT_MAX_PAYLOAD, command.length - offset);
    const next = new Uint8Array(PACKET_SIZE);
    next[4] = sequence;
    next.set(command.subarray(offset, offset + size), NEXT_DATA_OFFSET);
    chunks.push(next);
    offset += size;
    sequence += 1;
  }
  return chunks;
}

function descriptor(device) {
  return {
    productName: device.productName,
    manufacturerName: device.manufacturerName,
    serialNumber: device.serialNumber,
    vendorId: device.vendorId,
    productId: device.productId,
  };
}

function remainingTime(deadline) {
  const remaining = deadline - Date.now();
  if (remaining <= 0) {
    throw new ImKeyWebUsbError("APDU timeout", "webusb_apdu_timeout");
  }
  return remaining;
}

async function readChunk(device, endpoint, deadline) {
  const timeoutMs = remainingTime(deadline);
  let timer;
  try {
    const result = await Promise.race([
      device.transferIn(endpoint, PACKET_SIZE),
      new Promise((_, reject) => {
        timer = setTimeout(
          () =>
            reject(
              new ImKeyWebUsbError(
                `APDU timeout while reading endpoint ${endpoint}`,
                "webusb_apdu_timeout"
              )
            ),
          timeoutMs
        );
      }),
    ]);
    if (!result.data) {
      throw new ImKeyWebUsbError("Failed to read data from imKey.", "webusb_read_empty");
    }
    return new Uint8Array(result.data.buffer, result.data.byteOffset, result.data.byteLength);
  } finally {
    clearTimeout(timer);
  }
}

export async function readApduResponse(device, endpoint, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const deadline = Date.now() + timeoutMs;
  let first;
  do {
    first = await readChunk(device, endpoint, deadline);
  } while (first[4] === BUSY_INDICATOR);

  if (first.length < FIRST_DATA_OFFSET) {
    throw new ImKeyWebUsbError("Invalid WebUSB response header.", "webusb_invalid_response");
  }
  const totalLength = (first[5] << 8) | first[6];
  const response = new Uint8Array(totalLength);
  const firstSize = Math.min(FIRST_MAX_PAYLOAD, totalLength);
  response.set(first.subarray(FIRST_DATA_OFFSET, FIRST_DATA_OFFSET + firstSize));

  let offset = firstSize;
  let expectedSequence = 0;
  while (offset < totalLength) {
    const next = await readChunk(device, endpoint, deadline);
    if (next[4] === BUSY_INDICATOR) continue;
    if (next.length < NEXT_DATA_OFFSET || next[4] !== expectedSequence) {
      throw new ImKeyWebUsbError("Invalid WebUSB response sequence.", "webusb_invalid_response");
    }
    const size = Math.min(NEXT_MAX_PAYLOAD, totalLength - offset);
    response.set(next.subarray(NEXT_DATA_OFFSET, NEXT_DATA_OFFSET + size), offset);
    offset += size;
    expectedSequence += 1;
  }
  return response;
}

export async function findAndClaimEndpoints(device) {
  if (device.configuration === null) {
    await device.selectConfiguration(1);
  }
  const interfaces = device.configuration?.interfaces ?? [];
  const candidates = [];
  for (const iface of interfaces) {
    for (const alternate of iface.alternates) {
      const input = alternate.endpoints.find((endpoint) => endpoint.direction === "in");
      const output = alternate.endpoints.find((endpoint) => endpoint.direction === "out");
      if (!input || !output) continue;
      candidates.push({
        interfaceNumber: iface.interfaceNumber,
        interfaceClass: alternate.interfaceClass,
        inEndpoint: input.endpointNumber,
        outEndpoint: output.endpointNumber,
        packetSize: PACKET_SIZE,
      });
    }
  }

  candidates.sort((left, right) => {
    const leftVendor = left.interfaceClass === 255;
    const rightVendor = right.interfaceClass === 255;
    if (leftVendor !== rightVendor) return leftVendor ? -1 : 1;
    const leftReference = left.inEndpoint === 5 && left.outEndpoint === 4;
    const rightReference = right.inEndpoint === 5 && right.outEndpoint === 4;
    if (leftReference !== rightReference) return leftReference ? -1 : 1;
    return left.interfaceNumber - right.interfaceNumber;
  });

  const attempted = new Set();
  for (const candidate of candidates) {
    if (attempted.has(candidate.interfaceNumber)) continue;
    attempted.add(candidate.interfaceNumber);
    try {
      await device.claimInterface(candidate.interfaceNumber);
      const { interfaceClass: _, ...endpoints } = candidate;
      return endpoints;
    } catch {
      // Try the next descriptor candidate.
    }
  }
  throw new ImKeyWebUsbError(
    "No claimable WebUSB interface with in/out endpoints was found.",
    "webusb_interface_not_found"
  );
}

export class WebUsbImKeyTransport {
  #lock = Promise.resolve();
  #connected = true;
  #lastTrace = null;
  #usbApi = null;
  #disconnectListener = null;
  #identity;

  constructor(device, endpoints, usbApi = null) {
    this.device = device;
    this.endpoints = endpoints;
    this.#identity = descriptor(device);
    if (usbApi) this.#attachUsbApi(usbApi);
  }

  #attachUsbApi(api) {
    if (this.#usbApi && this.#disconnectListener) {
      this.#usbApi.removeEventListener("disconnect", this.#disconnectListener);
    }
    this.#usbApi = api;
    this.#disconnectListener = (event) => {
      if (event.device === this.device) this.markDisconnected();
    };
    api.addEventListener("disconnect", this.#disconnectListener);
  }

  #matchesIdentity(device) {
    if (
      device.vendorId !== this.#identity.vendorId ||
      device.productId !== this.#identity.productId
    ) {
      return false;
    }
    return !this.#identity.serialNumber || device.serialNumber === this.#identity.serialNumber;
  }

  async #exclusive(operation) {
    const previous = this.#lock;
    let release;
    this.#lock = new Promise((resolve) => {
      release = resolve;
    });
    try {
      await previous;
      return await operation();
    } finally {
      release();
    }
  }

  getDiagnostics() {
    return {
      connected: this.#connected && this.device.opened,
      descriptors: descriptor(this.device),
      endpoints: this.endpoints,
      lastTrace: this.#lastTrace,
    };
  }

  markDisconnected() {
    this.#connected = false;
  }

  async close() {
    await this.#exclusive(async () => {
      this.#connected = false;
      if (this.#usbApi && this.#disconnectListener) {
        this.#usbApi.removeEventListener("disconnect", this.#disconnectListener);
      }
      this.#disconnectListener = null;
      if (!this.device.opened) return;
      await this.device.releaseInterface(this.endpoints.interfaceNumber).catch(() => undefined);
      await this.device.close().catch(() => undefined);
    });
  }

  async sendApduRaw(apduHex, timeoutMs = DEFAULT_TIMEOUT_MS) {
    return this.#exclusive(async () => {
      if (!this.#connected || !this.device.opened) {
        throw new ImKeyWebUsbError("Device disconnected.", "webusb_device_disconnected");
      }
      const normalized = apduHex.trim().toUpperCase();
      const chunks = encodeApduChunks(normalized);
      for (const chunk of chunks) {
        await this.device.transferOut(this.endpoints.outEndpoint, chunk);
      }
      this.#lastTrace = {
        apdu: normalized,
        firstChunk: bytesToHex(chunks[0]),
        endpoints: this.endpoints,
      };
      try {
        const response = await readApduResponse(
          this.device,
          this.endpoints.inEndpoint,
          timeoutMs
        );
        const responseHex = bytesToHex(response);
        this.#lastTrace = { ...this.#lastTrace, response: responseHex };
        return responseHex;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new ImKeyWebUsbError(
          `${message}; apdu=${normalized}; endpoints=${JSON.stringify(this.endpoints)}`,
          error instanceof ImKeyWebUsbError ? error.code : "webusb_apdu_error"
        );
      }
    });
  }

  async reconnect(timeoutMs = 30_000) {
    return this.#exclusive(async () => {
      const api = this.#usbApi ?? usb();
      if (!this.#usbApi) this.#attachUsbApi(api);
      if (typeof api.getDevices !== "function") {
        throw new ImKeyWebUsbError(
          "WebUSB reconnect is unavailable.",
          "webusb_reconnect_unsupported"
        );
      }

      this.#connected = false;
      if (this.device.opened) {
        await this.device
          .releaseInterface(this.endpoints.interfaceNumber)
          .catch(() => undefined);
        await this.device.close().catch(() => undefined);
      }

      const deadline = Date.now() + Math.max(1, timeoutMs);
      while (Date.now() < deadline) {
        const devices = await api.getDevices().catch(() => []);
        const candidates = devices.filter((device) => this.#matchesIdentity(device));
        for (const candidate of candidates) {
          try {
            if (!candidate.opened) await candidate.open();
            const endpoints = await findAndClaimEndpoints(candidate);
            this.device = candidate;
            this.endpoints = endpoints;
            this.#connected = true;
            this.#lastTrace = null;
            return;
          } catch {
            await candidate.close().catch(() => undefined);
          }
        }
        await new Promise((resolve) => setTimeout(resolve, 250));
      }

      throw new ImKeyWebUsbError(
        "Timed out while reconnecting to imKey after firmware restart.",
        "webusb_reconnect_timeout"
      );
    });
  }
}

export async function connectImKeyWebUsb(filters = []) {
  const api = usb();
  let device;
  try {
    device = await api.requestDevice({ filters });
  } catch (error) {
    throw new ImKeyWebUsbError(
      error instanceof Error ? error.message : "WebUSB permission was cancelled.",
      "webusb_permission_cancelled"
    );
  }
  if (!device.opened) await device.open();
  const endpoints = await findAndClaimEndpoints(device);
  const transport = new WebUsbImKeyTransport(device, endpoints, api);
  return {
    get device() {
      return transport.device;
    },
    transport,
    get descriptors() {
      return descriptor(transport.device);
    },
    get endpoints() {
      return transport.endpoints;
    },
    async disconnect() {
      await transport.close();
    },
  };
}

export const IMKEY_WEBUSB_REFERENCE_DESCRIPTOR = Object.freeze({
  vendorId: 0x096e,
  productId: 0x0891,
  configuration: 1,
  interfaceNumber: 0,
  inEndpoint: 5,
  outEndpoint: 4,
  packetSize: PACKET_SIZE,
});
