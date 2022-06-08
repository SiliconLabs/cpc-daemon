# CPC Host Iostream Bridge
The CPC host code comes with the python script ***cpc_iostream_bridge.py*** under the **script** folder.

This can be used in conjunction with the ***cpc_iostream*** and ***cli*** components on the secondary side. Refer to the [CLI documentation](https://docs.silabs.com/gecko-platform/latest/service/cli/overview) and [IO stream documentation](https://docs.silabs.com/gecko-platform/latest/service/api/group-iostream) to se tup a CLI application on your secondary device.
Once your secondary application and the CPC daemon are running, calling the script opens the CLI endpoint on the host side and opens a network bridge to redirect any data received and transfered on the CPC CLI endpoint over to the network connection. Once the bridge is ready and listening, a telnet terminal can be opened to send and receive data over CPC CLI endpoint.

The ***cpc_iostream_bridge.py*** script takes 3 mandatory arguments: 
- -n, --name *INSTANCE_NAME*: The CPC daemon instance name
- -l, --library *LIB_NAME*: Path and name of the CPC library
- -p, --port *PORT_NUMBER*: Network bridge port number to use

And one optional argument (-v, --verbose) can be passed to enable verbose tracing.

Here is an example of a ***cpc_iostream_bridge.py*** usage:

    $ python cpc_iostream_bridge.py -n cpcd_0 -l build/libcpc.so -p 8080 -v
    BRIDGE: Listen OK
    BRIDGE: CPC Init success

You can then test the bridge by opening a telnet connection:

    $ telnet localhost 8080
    Trying 127.0.0.1...
    Connected to 127.0.0.1.
    Escape character is '^]'.