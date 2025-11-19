# IO Stream CPC Host Application

On the host side, use the Python script `cpc_iostream_bridge.py` to bridge the CPC host CLI endpoint to a network socket. This allows communication with the secondary device through a telnet terminal.

## CPC Host Iostream Bridge

The **cpc_iostream_bridge.py** script is used in conjunction with the **cpc_iostream** and **cli** components running on the secondary device. For proper operation, the CPC daemon must be up and running on the host side before starting the bridge script.

### Usage

The script accepts the following mandatory arguments:
- `-n, --name INSTANCE_NAME`: The CPC daemon instance name.
- `-l, --library LIB_NAME`: The path and name of the CPC library.
- `-p, --port PORT_NUMBER`: The network bridge port number to use.

An optional `-v, --verbose` flag is available for verbose output.

**Example:**

```bash
$ python cpc_iostream_bridge.py -n cpcd_0 -l build/libcpc.so -p 8080 -v
BRIDGE: Listen OK
BRIDGE: CPC Init success
```

Test the bridge by opening a telnet connection:

```bash
$ telnet localhost 8080
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
```
