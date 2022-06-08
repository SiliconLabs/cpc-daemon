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
mandatory. The allowed values are `UART` and `SPI`.
Depending on the bus type selected, certain configuration parameters that follow
are either required, optional, or ignored.

    bus_type: UART

### SPI Device File

Required when the bus type is `SPI`. The location on sysfs of the secondary
device.

    spi_device_file: /dev/spidev0.0

### SPI Chip Select GPIO

Required when the bus type is `SPI`. The number of the GPIO used for chip select.
Note that the pin must be available in user space.

    spi_cs_gpio: 8

### SPI Rx Interrupt GPIO
Required when the bus type is `SPI`. The SPI interface for CPC uses an additional
pin to indicate that a packet has been received by the CPCd.

    spi_rx_irq_gpio: 22

### SPI Bitrate

Optional when the bus type is `SPI`. The maximum transfer speed in Hz. Default value
is 1000000.

    spi_device_bitrate: 1000000

### SPI Mode

Optional when the bus type is `SPI`. The value must be one of `SPI_MODE_0`, `SPI_MODE_1`,
`SPI_MODE_2` or `SPI_MODE_3`. Default value is `SPI_MODE_0`.

    spi_device_mode: SPI_MODE_0

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

    bootloader_wake_gpio: 23

### Trace to Stdout

Optional boolean to enable tracing to stdout.  Default value is `false`.

    stdout_trace: false

### Trace to File

Optional boolean to enable tracing to file. A time-stamped file will be created in the folder
pointed by `traces_folder`.

    trace_to_file: false

### Traces Folder

Optional if `trace_to_file` is enabled. The folder where time-stamped trace files
will be saved. It is recommended that this point to a folder mounted on tmpfs.
Default value is `/dev/shm/cpcd-traces`.

    traces_folder: /dev/shm/cpcd-traces

### Enable Frame Traces

Optional if `stdout_trace` or `trace_to_file` is enabled. If enabled, traces will
include all frames transmitted and received. Default value is `false`.

    enable_frame_trace: false

### Allowable Number of Open File Descriptors

Optional parameter to set the allowable number of concurrently opened file
descriptors. Default is `1024`.

    rlimit_nofile: 1024

### Disable Encryption

Optional boolean to disable encryption. Default is `true` (encryption is disabled).

    disable_encryption: false

### Binding Key

Mandatory when `disable_encryption` is `false` (encryption is enabled). The location
on the filesystem of the binding key. The file must contain one line of 32 alphanumeric
characters representing a 128-bit key. If ECDH encryption is used, this file will
be created during the binding operation.

    binding_key_file: /etc/binding-key.key
