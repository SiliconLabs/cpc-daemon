# CPC Firmware Upgrade

The CPC daemon (CPCd) supports upgrade of the secondary's firmware in
standalone bootloader mode via UART XMODEM and SPI EZSP. The upgrade image 
must be in Gecko Bootloader (.gbl) format.

For this function to be available, the secondary must have the Gecko Bootloader
installed, and the secondary application image must be generated with the
component `bootloader_interface`.

For details about the Gecko Bootloader, see
[UG103.6: Bootloader Fundamentals](https://www.silabs.com/documents/public/user-guides/ug103-06-fundamentals-bootloading.pdf).

# Generation of the Upgrade Image

The upgrade image can be generated with Simplicity Commander from an
application image using the command:

    commander gbl create upgrade_image.gbl --app app.s37
  
For information about the Gecko Bootloader (.gbl) format, see
[UG489: Silicon Labs Gecko Bootloader User's Guide for GSDK 4.0 and Higher](https://www.silabs.com/documents/public/user-guides/ug489-gecko-bootloader-user-guide-gsdk-4.pdf).

# Initiating a Firmware Upgrade

To initiate a firmware upgrade, the CPCd must be stopped and restarted with
the command line argument `-f` or `--firmware-update`, followed by the
name of the firmware upgrade file.

    cpcd -c cpcd.conf -f upgrade_image.gbl

Once the secondary has rebooted into the bootloader, the CPCd will transfer
the firmware image to the secondary. When the transfer is complete, the CPCd
will exit. An exit code of `EXIT_SUCCESS` indicates that the transfer was successful.

# CPCd Configuration

## GPIO Activation

The CPCd can force the secondary to reboot into the bootloader via pins,
if GPIO Activation is enabled in the bootloader and the relevant pins (nWAKE and nRESET)
are connected. For more information about GPIO Activation, see
[UG489: Silicon Labs Gecko Bootloader User's Guide for GSDK 4.0 and Higher](https://www.silabs.com/documents/public/user-guides/ug489-gecko-bootloader-user-guide-gsdk-4.pdf).

In order to take advantage of this feature, ensure that the following
parameters are configured in cpcd.conf:

    bootloader_recovery_pins_enabled: true
    bootloader_wake_gpio: nWAKE gpio
    bootloader_reset_gpio: nRESET gpio

## CPC Activation

If GPIO Activation is **not** supported, `bootloader_recovery_pins_enabled`
must be configured to `false`. In this case, the CPCd will send a request via
the CPC protocol to the secondary application to reboot itself into the bootloader.

**Note** If CPC Activation is used, it is very important that the interface settings of
the bootloader be configured the same as the CPC host and secondary. In particular,
if UART is used, the baudrate and flow control must be consistent, and for SPI,
the interrupt pin must be the same for the bootloader and secondary application.

If this is not possible, it is possible to reboot the secondary into the bootloader
and transfer the firmware image to bootloader in two separate steps. In this way,
different configurations can be used for the secondary application and the bootloader.

    cpcd -c application.conf --enter-bootloader
    cpcd -c bootloader.conf --connect-to-bootloader --firmware-update upgrade_image.gbl

The `connect-to-bootloader` option may also be useful in the case where the transfer
fails and the secondary stays in bootloader.

# Security Considerations

Note that, even if security is enabled in the CPCd, the upgrade transfer will
not use CPC encryption, as the CPC protocol is not supported by the bootloader.
