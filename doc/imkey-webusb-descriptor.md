# imKey Pro WebUSB Descriptor

The SDK uses descriptor discovery as the source of truth. The values below are
the confirmed imKey Pro reference values used by the current device and the
`web.imkey.im` implementation:

| Field | Reference value |
| --- | --- |
| Vendor ID | `0x096E` (`2414`) |
| Product ID | `0x0891` (`2193`) |
| Configuration | `1` |
| Preferred interface class | vendor specific (`255`) |
| Reference interface number | `0` |
| Reference IN endpoint | `5` |
| Reference OUT endpoint | `4` |
| Packet size | `64` bytes |

The browser adapter does not assume that interface `0` or endpoints `5/4` are
always present. It scans interface descriptors for a claimable interface with
both IN and OUT endpoints, prefers vendor-specific interfaces, and uses the
reported endpoint numbers. The reference VID/PID can be supplied as a WebUSB
filter by a product integration, while the SDK default keeps an empty filter to
support authorized development devices and future descriptor variants.
