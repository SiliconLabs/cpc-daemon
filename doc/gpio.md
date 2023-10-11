# CPC GPIO Interfaces

The CPC daemon (CPCd) supports two gpio interfaces: sysfs and gpiod.
The sysfs interface is currently the default interface when building the daemon.

# Sysfs

To use the sysfs interface,

- Your kernel must be built with `CONFIG_GPIO_SYSFS`.
- You must configure `cpcd.conf` to map the IRQ pin: 
  - `spi_rx_irq_gpio`
- If the bootloader recovery pins are enabled (i.e., "bootloader_recovery_pins_enabled: true" in configuration file), you must also configure:
  - `bootloader_wake_gpio`
  - `bootloader_reset_gpio`


# Gpiod

To use the gpiod interface, 

- You must have `libgpiod-dev` installed.
- You must build the project with the following parameter: `-DUSE_LEGACY_GPIO_SYSFS=FALSE`
- You must configure `cpcd.conf` to map the proper IRQ chip and pin:
  - `spi_rx_irq_gpio_chip` & `spi_rx_irq_gpio`
- If the bootloader recovery pins are enabled (i.e., "bootloader_recovery_pins_enabled: true" in configuration file), you must also configure:
  - `bootloader_wake_gpio_chip` & `bootloader_wake_gpio`
  - `bootloader_reset_gpio_chip` & `bootloader_reset_gpio`

# Chip select line

If the daemon is used in SPI mode, the chip select pin is not under control of the daemon. Instead, it is under the control of the kernel.
This means that for a given SPI port 'X', the kernel will list multiple "/dev/spidevX.Y" depending on the number of chip select line 'Y' under its control.
To use a particular chip select, make sure the right /dev/spidevX.Y is given in the configuration file.
This means that you can have multiple secondary devices hooked in the same SPI bus with each its own chip select.
As long as the kernel knows about each chip select line, starting a daemon and connecting to each of them simultaneously is fully supported.

How to achieve the chip select configuration for a given SPI port is setup dependant and most likely involves altering the device-tree.

To do it on a raspberry pi, one can use the convenient device-tree-overlays already present on the distribution:
In the file "/boot/config.txt", for the SPI port available on the pin header, add one of the following lines,
depending on how many chip select lines you want (with the overlays provided out of the box, up to 2 chip select lines are supported):

dtoverlay=spi0-1cs,cs0_pin=X
dtoverlay=spi0-2cs,cs0_pin=X,cs1_pin=Y
