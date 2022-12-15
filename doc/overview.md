# CPCd Overview
The purpose of the Co-Processor Protocol (CPC) is to act as a serial link multiplexer
that allows data sent from multiple applications to be transported over a secure shared physical link.

The CPC daemon (CPCd) allows applications on Linux to interact with a secondary running CPC.
It acts as a multiplexer to enable multiple host applications to communicate via the
CPC protocol without worrying about collisions.

In CPC, data transfers between processors are segmented in sequential packets over endpoints.
Transfers are guaranteed to be error-free and sent in order.

CPCd uses Unix sockets configured as sequential packets to transfer data with
the Linux host applications. Data is then forwarded to the co-processor over the
serial link. Host applications use the CPC Library (libcpc.so) to interact with the daemon.

Three components are distributed: the daemon binary `cpcd`, a library that
enables `C` applications to interact with the daemon `libcpc.so`, and a configuration file `cpcd.conf`.

Additional CPCd features include:
- Encryption of the serial link with a bound secondary.
- Initiate a firmware update for the secondary
- Validate the UART RX/TX and CTS/RTS connections with the secondary.

![](CPC_Building_blocks.svg "CPC Building blocks")

![](CPC_Diagram.svg "CPCD Diagram")

