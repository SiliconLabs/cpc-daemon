# Python Bindings

Python bindings are provided to interact with libcpc. They are provided as a
standalone module in `libcpc_wrapper.py` in the `script` directory.

## Sample Code

    # don't forget to add the script directory to PYTHONPATH
    # to import the module successfully
    import libcpc_wrapper

    def on_reset():
        print("Daemon has reset")

    # Arguments are:
    #  - path to the library
    #  - cpc daemon instance name
    #  - enable library tracing
    #  - on reset callback
    cpc = libcpc_wrapper.CPC("/usr/lib/libcpc.so", "cpcd_0", False, on_reset)

    # Open an endpoint. Use an integer value or a predefined value
    endpoint = cpc.open_endpoint(libcpc_wrapper.Endpoint.Id.CLI)

    # Write data to the endpoint. This function expects a bytearray
    size = 42
    buf = bytearray(size)
    endpoint.write(buf)

    # Read data from endpoint. This function returns a bytearray
    buf = endpoint.read()

    # Close endpoint
    endpoint.close()
