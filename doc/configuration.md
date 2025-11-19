# CPC Daemon Configuration

The CPC daemon (CPCd) requires a configuration file. The file uses a simple YAML
format of case-sensitive `key: value` pairs. Any characters following a `#` are
considered comments and are ignored.
A default configuration is installed in `/usr/local/etc/cpcd.conf`.
The configuration file location can also be passed to the daemon using the `-c/--conf` argument.

    cpcd --conf ./cpc_config.conf

## Configuration Parameters

### Instance Name

The optional `instance_name` parameter defines the name that will be assigned to the
listening socket of the daemon. Each instance of the daemon that runs on the host
must have a distinct instance name. An application can pass the instance name to
cpc_init() in order to connect to a particular instance of the daemon. The default
value of `instance_name` is `cpcd_0`.

    instance_name: cpcd_0

### Bus Type

The bus used to connect the host to the secondary. The bus_type parameter is
mandatory. The allowed values are `UART`, `SPI` and `NETLINK_SDIO`.
Depending on the bus type selected, certain configuration parameters that follow
are either required, optional, or ignored.

    bus_type: UART

### SPI Device File

Required when the bus type is `SPI`. The location on sysfs of the secondary
device.

    spi_device_file: /dev/spidev0.0

### SPI Rx Interrupt GPIO
Required when the bus type is `SPI`. The SPI interface for CPC uses an additional
pin to indicate that a packet has been received by the CPCd.

    spi_rx_irq_gpio: 22

### SPI Bitrate

Optional when the bus type is `SPI`. The maximum transfer speed in Hz. Default value
is 1000000.

    spi_device_bitrate: 1000000

### SDIO Reset Sequence

Setting reset sequence to `false` would typically imply that the sequence should continue without being resetting the secondary.

    reset_sequence: false


### UART Device File

Required when the bus type is `UART`. The location on sysfs of the secondary
device.

    uart_device_file: /dev/ttyACM0

### UART Baud Rate

Optional when the bus type is `UART`. Default value is 115200.

    uart_device_baud: 115200

### UART Flow Control

Optional when the bus type is `UART`. Boolean to enable or disable hardware flow control.
Default value is `true`

    uart_hardflow: true

### BOOTLOADER Recovery Pins Enabled

Boolean to indicate that the RESET and WAKE pins of the secondary are connected, allowing
a hardware reset into bootloader. This feature can be used for upgrading the firmware of the
secondary. If set to `true`, bootloader_wake_gpio and bootloader_reset_gpio must be configured.
Default value is `false`.

    bootloader_recovery_pins_enabled: false

### BOOTLOADER Wake GPIO

Required if `bootloader_recovery_pins_enabled` is set to `true`. The number of the GPIO
that is connected to the WAKE pin of the secondary.

    bootloader_wake_gpio: 24

### BOOTLOADER Reset GPIO

Required if `bootloader_recovery_pins_enabled` is set to `true`. The number of the GPIO
that is connected to the RESET pin of the secondary.

    bootloader_reset_gpio: 23

### Trace level

Optional parameter to control the level of tracing information output to stdout.
The default value is `info` and remains `info` until the `trace_level` option is parsed. Allowed values are:

- `error` - Errors only
- `warn` - Warnings and above
- `info` - Informational messages and above (default)
- `debug` - Debug messages (endpoint, driver, core, security, etc.) and above
- `frame` - Frame tracing and above

Example:

    trace_level: info

### Trace to File

Optional boolean to enable tracing to file. A time-stamped file will be created in the folder
pointed by `traces_folder`.

    trace_to_file: false

### Traces Folder

Optional if `trace_to_file` is enabled. The folder where time-stamped trace files
will be saved. It is recommended that this point to a folder mounted on tmpfs.
Default value is `/dev/shm/cpcd-traces`.

    traces_folder: /dev/shm/cpcd-traces

### Allowable Number of Open File Descriptors

Optional parameter to set the allowable number of concurrently opened file
descriptors. Default is `1024`.

    rlimit_nofile: 1024

### Disable Encryption

Optional boolean to disable encryption. Default is `false` (encryption is enabled).

    disable_encryption: false

### Binding Key

Mandatory when `disable_encryption` is `false` (encryption is enabled). The location
on the filesystem of the binding key. The file must contain one line of 32 alphanumeric
characters representing a 128-bit key. If ECDH encryption is used, this file will
be created during the binding operation.

    binding_key_file: ~/.cpcd/binding.key

### Multicast Endpoints

This configuration controls whether multiple clients can simultaneously open, write to, and receive data from a given endpoint. When multicast is disabled for an endpoint, only a single client can open and use the endpoint at a time; any additional attempts to open the endpoint will be denied until the existing handle is closed. Note that a client is precisely a libcpc `cpc_endpoint_t` handle which may exist across the same or different processes/threads.

This configuration is optional and if it is not present in the configuration file, multicasting is enabled for all endpoints by default. If it is present, multicasting is enabled *only* for the endpoints specified in the list. Each endpoint ID must be a number between `0` and `255`, or a range in the form `start-end` (e.g., `12-20`). Here are some examples:

This would enable multicasting for endpoints 10 and 90, while preventing it for all other endpoints:

    multicast_endpoints: [10, 90]

This would enable multicasting for endpoints 12, 15, 16, 17, 18, 19, 20, and 25:

    multicast_endpoints: [12, 15-20, 25]

This would disable multicasting for all endpoints:

    multicast_endpoints: []

This would enable multicasting for all endpoints:

    multicast_endpoints: [0-255]

This would also enable multicasting for all endpoints as the configuration is commented (`#`) out:

    #multicast_endpoints: []

