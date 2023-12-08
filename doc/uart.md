# UART Security Concerns

UART is an asynchronous protocol. In order to detect valid packets
within the stream of bytes being received, CPC tries to locate HDLC
headers. HDLC headers are composed of:
 - a start byte (0x14)
 - four bytes with various information
 - two bytes of checksum.

If the packet has a payload, then it's right after the header and ends
with two bytes of checksum.

Most of the time, CPC can keep up with the incoming flow of bytes and is
in 'synced' mode, packets are found one after the other. Sometimes, when
an invalid packet is found, CPC switches to 'resync' mode and keeps
scanning the incoming bytes for an HDLC header.

In that mode, if the user data contain a valid HDLC packet, CPC might
resync on that packet instead of the containing one, like in the example
below:

```
+----------------+-----------------------------------------------------+
|                | User Payload contains an HDLC packet and other data |
|   HDLC Header  |  +----------------+------------------------------+  |
|                |  |   HLDC Header  |       Sub-Payload            |  |
|                |  +----------------|------------------------------+  |
+----------------+-----------------------------------------------------|
```

In that case, the endpoint will receive only the 'Sub-Payload' and not
the whole user payload. Chances of that happening are quite thin but
they exist:
 - CPC must be in resync mode
 - there must be a valid HDLC packet somewhere in the byte stream that
   is not part of CPC's HDLC packets.

To mitigate this possibility, enable the security or switch to SPI.
