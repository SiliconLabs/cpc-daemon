# Python Bindings

Python bindings are provided to interact with libcpc. They are provided as a
standalone module in `libcpc.py` in the `lib/bindings/python` directory.

## Sample Code

    # don't forget to add the binding directory to PYTHONPATH
    # to import the module successfully. Refer to the documentation
    # in lib/bindings/python directory for more details.
    import libcpc

    def on_reset():
        print("Daemon has reset")

    # Arguments are:
    #  - path to the library
    #  - cpc daemon instance name
    #  - enable library tracing
    #  - on reset callback
    cpc = libcpc.CPC("/usr/lib/libcpc.so", "cpcd_0", False, on_reset)

    # Open an endpoint. Use an integer value or a predefined value
    endpoint = cpc.open_endpoint(libcpc.Endpoint.Id.CLI)

    # Write data to the endpoint. This function expects a bytearray
    size = 42
    buf = bytearray(size)
    endpoint.write(buf)

    # Read data from endpoint. This function returns a bytearray
    buf = endpoint.read()

    # Close endpoint
    endpoint.close()
