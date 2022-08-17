# CPC GPIO Interfaces

The CPC daemon (CPCd) supports two gpio interfaces: sysfs and gpiod.
The sysfs interface is currently the default interface when building the daemon.

# Sysfs

To use the sysfs interface,

- Your kernel must be built with `CONFIG_GPIO_SYSFS`.
- You must configure` cpcd.conf` to map the proper pins: 
  - `spi_cs_gpio`
  - `spi_rx_irq_gpio`
  - `bootloader_wake_gpio`
  - `bootloader_reset_gpio`


# Gpiod

To use the gpiod interface, 

- You must have `libgpiod-dev` installed.
- You must build the project with the following parameter:` -DENABLE_GPIOD=TRUE` or set the `ENABLE_GPIOD` flag to `TRUE` in `CMakeLists.txt`
- You must configure `cpcd.conf` to map the proper chips and pins: 
  - `spi_cs_gpio_chip` & `spi_cs_gpio`
  - `spi_rx_irq_gpio_chip` & `spi_rx_irq_gpio`
  - `bootloader_wake_gpio_chip` & `bootloader_wake_gpio`
  - `bootloader_reset_gpio_chip` & `bootloader_reset_gpio`
