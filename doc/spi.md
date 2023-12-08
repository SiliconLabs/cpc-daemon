# SPI Bitrate
When using the SPI interface, the bus bitrate is controlled by the host/primary. The chosen bitrate is selected using the following logic:

- The primary will initiate communication with the secondary with a fixed conservative bitrate of 1MHz and retrieve the maximum bitrate supported by the secondary.

- If the parameter `spi_device_bitrate` is not specified in the configuration file, the host/primary will use the maximum supported bitrate returned by the secondary, which will be:
  - 10 MHz when using the EUSART peripheral
  - PCLK / 10 when using the USART peripheral.

- else if the parameter `spi_device_bitrate` is specified in the configuration file, that bitrate will be used unless it is greater than the maximum bitrate returned by the secondary, in which case the maximum bitrate will be used instead, and a warning will be printed.

# Upgrading from Version 4.2 or Lower to Version 4.3 and Beyond
Follow the following steps to complete an upgrade
1. Build a New Secondary Image:
  - Create a new secondary image using a more recent version of CPC secondary.
2. Perform Firmware Upgrade:
  - Upgrade the firmware of your secondary using your existing CPCd.
  - After the upgrade, your existing CPCd version will no longer be able to communicate with the secondary.
3. Update Linux System:
  - Update your Linux system to assign your SPI device's GPIO for Chip Select (CS). As an example for an ARM-based Host, you must update your device tree.
4. Build a New CPCd:
  - Build a new CPCd that matches the version of your upgraded secondary.
5. Update cpcd.conf file:
  - Modify the cpcd.conf file to reflect the changes for your SPI device.
  - Review the `spi_device_file` setting and ensure it matches your configuration.
  - Remove the `spi_cs_gpio` entry from the config file, as it will be ignored.
6. Start the New CPCd:
  - Launch the new CPCd process.
  - Verify that the new CPCd is now able to communicate successfully with the upgraded secondary.
