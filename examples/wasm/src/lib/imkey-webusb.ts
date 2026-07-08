type UsbDirection = "in" | "out";

interface UsbEndpoint {
  direction: UsbDirection;
  endpointNumber: number;
}

interface UsbAlternateInterface {
  interfaceClass: number;
  interfaceSubclass?: number;
  interfaceProtocol?: number;
  endpoints: UsbEndpoint[];
}

interface UsbInterface {
  interfaceNumber: number;
  alternates: UsbAlternateInterface[];
}

interface UsbConfiguration {
  interfaces: UsbInterface[];
}

interface UsbDevice {
  opened: boolean;
  productName?: string;
  manufacturerName?: string;
  serialNumber?: string;
  vendorId: number;
  productId: number;
  configuration: UsbConfiguration | null;
  open(): Promise<void>;
  close(): Promise<void>;
  selectConfiguration(configurationValue: number): Promise<void>;
  claimInterface(interfaceNumber: number): Promise<void>;
  releaseInterface(interfaceNumber: number): Promise<void>;
  transferOut(endpointNumber: number, data: BufferSource): Promise<unknown>;
  transferIn(
    endpointNumber: number,
    length: number
  ): Promise<{ data?: DataView }>;
}

interface UsbDeviceFilter {
  vendorId?: number;
  productId?: number;
}

interface Usb {
  requestDevice(options: { filters: UsbDeviceFilter[] }): Promise<UsbDevice>;
  getDevices(): Promise<UsbDevice[]>;
  addEventListener(
    type: "disconnect",
    listener: (event: { device: UsbDevice }) => void
  ): void;
  removeEventListener(
    type: "disconnect",
    listener: (event: { device: UsbDevice }) => void
  ): void;
}

export interface ImKeyDeviceDescriptor {
  productName?: string;
  manufacturerName?: string;
  serialNumber?: string;
  vendorId: number;
  productId: number;
}

export interface EndpointConfig {
  interfaceNumber: number;
  inEndpoint: number;
  outEndpoint: number;
  packetSize: number;
}

export interface TransportTrace {
  apdu?: string;
  firstChunk?: string;
  response?: string;
  endpoints: EndpointConfig;
}

export interface ImKeyWebUsbSession {
  device: UsbDevice;
  transport: WebUsbImKeyTransport;
  descriptors: ImKeyDeviceDescriptor;
  endpoints: EndpointConfig;
  disconnect(): Promise<void>;
}

const PACKET_SIZE = 64;
const FIRST_DATA_OFFSET = 7;
const NEXT_DATA_OFFSET = 5;
const FIRST_MAX_PAYLOAD = PACKET_SIZE - FIRST_DATA_OFFSET;
const NEXT_MAX_PAYLOAD = PACKET_SIZE - NEXT_DATA_OFFSET;
const CMD_MESSAGE = 0xc3;
const BUSY_INDICATOR = 0xff;
const DEFAULT_TIMEOUT_MS = 20_000;
const READ_DELAY_MS = 10;

export class ImKeyWebUsbError extends Error {
  constructor(
    message: string,
    public readonly code: string
  ) {
    super(message);
    this.name = "ImKeyWebUsbError";
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function usb(): Usb {
  const maybeUsb = (navigator as Navigator & { usb?: Usb }).usb;
  if (!maybeUsb) {
    throw new ImKeyWebUsbError(
      "WebUSB is not supported. Please use Chrome or Edge.",
      "webusb_unsupported"
    );
  }
  return maybeUsb;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.trim().replace(/^0x/i, "");
  if (normalized.length % 2 !== 0 || /[^a-fA-F0-9]/.test(normalized)) {
    throw new ImKeyWebUsbError("Invalid APDU hex string.", "invalid_apdu_hex");
  }
  const bytes = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function viewToBytes(view: DataView): Uint8Array {
  return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
}

function descriptor(device: UsbDevice): ImKeyDeviceDescriptor {
  return {
    productName: device.productName,
    manufacturerName: device.manufacturerName,
    serialNumber: device.serialNumber,
    vendorId: device.vendorId,
    productId: device.productId,
  };
}

function chunkHex(chunk: Uint8Array): string {
  return bytesToHex(chunk);
}

async function writeChunk(
  device: UsbDevice,
  outEndpoint: number,
  chunk: Uint8Array
): Promise<void> {
  await device.transferOut(outEndpoint, chunk as BufferSource);
}

async function writeApdu(
  device: UsbDevice,
  outEndpoint: number,
  commandBytes: Uint8Array
): Promise<string> {
  const totalLength = commandBytes.length;
  let offset = 0;

  const firstPayloadSize = Math.min(FIRST_MAX_PAYLOAD, totalLength);
  const firstChunk = new Uint8Array(PACKET_SIZE);
  firstChunk[4] = CMD_MESSAGE;
  firstChunk[5] = (totalLength >> 8) & 0xff;
  firstChunk[6] = totalLength & 0xff;
  firstChunk.set(commandBytes.subarray(0, firstPayloadSize), FIRST_DATA_OFFSET);
  const firstChunkHex = chunkHex(firstChunk);
  console.debug("imKey WebUSB first chunk", firstChunkHex);
  await writeChunk(device, outEndpoint, firstChunk);
  offset += firstPayloadSize;

  let sequence = 0;
  while (offset < totalLength) {
    const payloadSize = Math.min(NEXT_MAX_PAYLOAD, totalLength - offset);
    const nextChunk = new Uint8Array(PACKET_SIZE);
    nextChunk[4] = sequence;
    nextChunk.set(
      commandBytes.subarray(offset, offset + payloadSize),
      NEXT_DATA_OFFSET
    );
    console.debug("imKey WebUSB next chunk", chunkHex(nextChunk));
    await writeChunk(device, outEndpoint, nextChunk);
    offset += payloadSize;
    sequence += 1;
  }

  return firstChunkHex;
}

async function readChunk(
  device: UsbDevice,
  inEndpoint: number,
  timeoutMs: number
): Promise<Uint8Array> {
  const result = await Promise.race([
    device.transferIn(inEndpoint, PACKET_SIZE),
    new Promise<never>((_, reject) =>
      setTimeout(
        () =>
          reject(
            new ImKeyWebUsbError(
              `APDU timeout while reading endpoint ${inEndpoint}`,
              "webusb_apdu_timeout"
            )
          ),
        timeoutMs
      )
    ),
  ]);
  await delay(READ_DELAY_MS);
  if (!result.data) {
    throw new ImKeyWebUsbError("Failed to read data from imKey.", "webusb_read_empty");
  }
  return viewToBytes(result.data);
}

async function readApdu(
  device: UsbDevice,
  inEndpoint: number,
  timeoutMs: number
): Promise<Uint8Array> {
  let header: Uint8Array;
  let start = Date.now();
  while (true) {
    if (Date.now() - start > timeoutMs) {
      throw new ImKeyWebUsbError("APDU timeout", "webusb_apdu_timeout");
    }
    header = await readChunk(device, inEndpoint, timeoutMs);
    if (header[4] === BUSY_INDICATOR) {
      start = Date.now();
      continue;
    }
    break;
  }

  const totalLength = (header[5] << 8) | header[6];
  const response = new Uint8Array(totalLength);
  const firstBytes = Math.min(FIRST_MAX_PAYLOAD, totalLength);
  response.set(header.subarray(FIRST_DATA_OFFSET, FIRST_DATA_OFFSET + firstBytes));
  let offset = firstBytes;

  while (offset < totalLength) {
    const next = await readChunk(device, inEndpoint, timeoutMs);
    if (next[4] === BUSY_INDICATOR) {
      continue;
    }
    const bytesNeeded = Math.min(NEXT_MAX_PAYLOAD, totalLength - offset);
    response.set(next.subarray(NEXT_DATA_OFFSET, NEXT_DATA_OFFSET + bytesNeeded), offset);
    offset += bytesNeeded;
  }

  return response;
}

async function findAndClaimEndpoints(device: UsbDevice): Promise<EndpointConfig> {
  await device.selectConfiguration(1);

  const webUsbInterface = device.configuration?.interfaces[0];
  if (webUsbInterface) {
    try {
      await device.claimInterface(webUsbInterface.interfaceNumber);
      return {
        interfaceNumber: webUsbInterface.interfaceNumber,
        inEndpoint: 5,
        outEndpoint: 4,
        packetSize: PACKET_SIZE,
      };
    } catch {
      // Fall through to descriptor-based probing below.
    }
  }

  const interfaces = device.configuration?.interfaces ?? [];
  const candidates: Array<{
    interfaceNumber: number;
    interfaceClass: number;
    endpoints: EndpointConfig;
  }> = [];

  for (const iface of interfaces) {
    const alternate = iface.alternates[0];
    if (!alternate) continue;

    let inEndpoint = 0;
    let outEndpoint = 0;
    for (const endpoint of alternate.endpoints) {
      if (endpoint.direction === "in") inEndpoint = endpoint.endpointNumber;
      if (endpoint.direction === "out") outEndpoint = endpoint.endpointNumber;
    }
    if (!inEndpoint || !outEndpoint) continue;

    candidates.push({
      interfaceNumber: iface.interfaceNumber,
      interfaceClass: alternate.interfaceClass,
      endpoints: {
        interfaceNumber: iface.interfaceNumber,
        inEndpoint,
        outEndpoint,
        packetSize: PACKET_SIZE,
      },
    });
  }

  candidates.sort((left, right) => {
    const leftDefault = left.endpoints.inEndpoint === 5 && left.endpoints.outEndpoint === 4;
    const rightDefault = right.endpoints.inEndpoint === 5 && right.endpoints.outEndpoint === 4;
    if (leftDefault !== rightDefault) return leftDefault ? -1 : 1;
    const leftVendor = left.interfaceClass === 255;
    const rightVendor = right.interfaceClass === 255;
    if (leftVendor !== rightVendor) return leftVendor ? -1 : 1;
    return left.interfaceNumber - right.interfaceNumber;
  });

  for (const candidate of candidates) {
    try {
      await device.claimInterface(candidate.interfaceNumber);
      return candidate.endpoints;
    } catch {
      continue;
    }
  }

  const dump = interfaces
    .map((iface) => {
      const alternate = iface.alternates[0];
      const endpoints =
        alternate?.endpoints
          .map((endpoint) => `${endpoint.direction}(${endpoint.endpointNumber})`)
          .join(",") ?? "none";
      return `Ifc${iface.interfaceNumber}: class=${alternate?.interfaceClass}, subclass=${alternate?.interfaceSubclass}, protocol=${alternate?.interfaceProtocol}, endpoints=${endpoints}`;
    })
    .join(" | ");

  throw new ImKeyWebUsbError(
    `No claimable WebUSB interface with in/out endpoints was found. ${dump}`,
    "webusb_interface_not_found"
  );
}

export class WebUsbImKeyTransport {
  private lock: Promise<void> = Promise.resolve();
  private connected = true;
  private lastTrace: TransportTrace | null = null;

  constructor(
    private readonly device: UsbDevice,
    private readonly endpoints: EndpointConfig
  ) {}

  getDiagnostics() {
    return {
      connected: this.connected && this.device.opened,
      descriptors: descriptor(this.device),
      endpoints: this.endpoints,
      lastTrace: this.lastTrace,
    };
  }

  markDisconnected(): void {
    this.connected = false;
  }

  async close(): Promise<void> {
    this.connected = false;
    if (this.device.opened) {
      await this.device.releaseInterface(this.endpoints.interfaceNumber).catch(() => undefined);
      await this.device.close().catch(() => undefined);
    }
  }

  async sendApduRaw(apduHex: string, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<string> {
    const previous = this.lock;
    let release!: () => void;
    this.lock = new Promise((resolve) => {
      release = resolve;
    });

    try {
      await previous;
      if (!this.connected || !this.device.opened) {
        throw new ImKeyWebUsbError("Device disconnected.", "webusb_device_disconnected");
      }
      const normalized = apduHex.toUpperCase();
      console.debug(">>> imKey APDU", {
        apdu: normalized,
        endpoints: this.endpoints,
      });
      const firstChunk = await writeApdu(
        this.device,
        this.endpoints.outEndpoint,
        hexToBytes(normalized)
      );
      this.lastTrace = {
        apdu: normalized,
        firstChunk,
        endpoints: this.endpoints,
      };
      let response: Uint8Array;
      try {
        response = await readApdu(this.device, this.endpoints.inEndpoint, timeoutMs);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new ImKeyWebUsbError(
          `${message}; apdu=${normalized}; endpoints=${JSON.stringify(this.endpoints)}`,
          error instanceof ImKeyWebUsbError ? error.code : "webusb_apdu_error"
        );
      }
      const responseHex = bytesToHex(response);
      this.lastTrace = {
        apdu: normalized,
        firstChunk,
        response: responseHex,
        endpoints: this.endpoints,
      };
      console.debug("<<< imKey APDU", {
        response: responseHex,
        endpoints: this.endpoints,
      });
      return responseHex;
    } finally {
      release();
    }
  }
}

export async function connectImKeyWebUsb(
  filters: UsbDeviceFilter[] = []
): Promise<ImKeyWebUsbSession> {
  const usbApi = usb();
  let device: UsbDevice;
  try {
    device = await usbApi.requestDevice({ filters });
  } catch (error) {
    throw new ImKeyWebUsbError(
      error instanceof Error ? error.message : "WebUSB permission was cancelled.",
      "webusb_permission_cancelled"
    );
  }
  if (!device.opened) {
    await device.open();
  }
  const endpoints = await findAndClaimEndpoints(device);
  const transport = new WebUsbImKeyTransport(device, endpoints);
  const onDisconnect = (event: { device: UsbDevice }) => {
    if (event.device === device) {
      transport.markDisconnected();
      usbApi.removeEventListener("disconnect", onDisconnect);
    }
  };
  usbApi.addEventListener("disconnect", onDisconnect);

  return {
    device,
    endpoints,
    descriptors: descriptor(device),
    transport,
    disconnect: async () => {
      usbApi.removeEventListener("disconnect", onDisconnect);
      await transport.close();
    },
  };
}
