export interface ImKeyUsbFilter {
  vendorId?: number;
  productId?: number;
}

export interface ImKeyUsbDevice {
  opened: boolean;
  productName?: string;
  manufacturerName?: string;
  serialNumber?: string;
  vendorId: number;
  productId: number;
  configuration: {
    interfaces: Array<{
      interfaceNumber: number;
      alternates: Array<{
        interfaceClass: number;
        endpoints: Array<{ direction: "in" | "out"; endpointNumber: number }>;
      }>;
    }>;
  } | null;
  open(): Promise<void>;
  close(): Promise<void>;
  selectConfiguration(value: number): Promise<void>;
  claimInterface(interfaceNumber: number): Promise<void>;
  releaseInterface(interfaceNumber: number): Promise<void>;
  transferOut(endpointNumber: number, data: BufferSource): Promise<unknown>;
  transferIn(endpointNumber: number, length: number): Promise<{ data?: DataView }>;
}

export interface ImKeyDeviceDescriptor {
  productName?: string;
  manufacturerName?: string;
  serialNumber?: string;
  vendorId: number;
  productId: number;
}

export interface ImKeyEndpointConfig {
  interfaceNumber: number;
  inEndpoint: number;
  outEndpoint: number;
  packetSize: number;
}

export interface ImKeyTransportTrace {
  apdu?: string;
  firstChunk?: string;
  response?: string;
  endpoints: ImKeyEndpointConfig;
}

export class ImKeyWebUsbError extends Error {
  readonly code: string;
  constructor(message: string, code: string);
}

export class WebUsbImKeyTransport {
  constructor(device: ImKeyUsbDevice, endpoints: ImKeyEndpointConfig);
  sendApduRaw(apduHex: string, timeoutMs?: number): Promise<string>;
  close(): Promise<void>;
  markDisconnected(): void;
  getDiagnostics(): {
    connected: boolean;
    descriptors: ImKeyDeviceDescriptor;
    endpoints: ImKeyEndpointConfig;
    lastTrace: ImKeyTransportTrace | null;
  };
}

export interface ImKeyWebUsbSession {
  device: ImKeyUsbDevice;
  transport: WebUsbImKeyTransport;
  descriptors: ImKeyDeviceDescriptor;
  endpoints: ImKeyEndpointConfig;
  disconnect(): Promise<void>;
}

export function connectImKeyWebUsb(filters?: ImKeyUsbFilter[]): Promise<ImKeyWebUsbSession>;
export const IMKEY_WEBUSB_REFERENCE_DESCRIPTOR: Readonly<{
  vendorId: number;
  productId: number;
  configuration: number;
  interfaceNumber: number;
  inEndpoint: number;
  outEndpoint: number;
  packetSize: number;
}>;
