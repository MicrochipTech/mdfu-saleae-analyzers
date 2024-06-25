# Microchip Device Firmware Update (MDFU) analyzers extension for Saleae

This extension includes the following analyzers:
- MDFU serial transport analyzer
- MDFU SPI transport analyzer

## MDFU serial transport analyzer
![MDFU serial transport Client Info Command](images/mdfu_serial_transport_client_info_cmd.png)

### Getting started

The MDFU serial transport analyzer decodes serial traffic.


### Analyzer settings

The `Trace` setting defines whether the analyzer decodes the traffic from or to the host. To fully decode serial traffic, two MDFU serial analyzers must be added, one to decode traffic coming from the host and the second one to decode traffic to the host.

## MDFU SPI transport analyzer Saleae extension

![Decoded MDFU SPI Get Client Info command transaction](images/mdfu_spi_client_info.png)

### Getting started

The Microchip Device Firmware Update (MDFU) SPI transport analyzer decodes the traffic on the SPI bus and enables an in depth view of the protocol.

The analyzer requires a valid capture of the SPI bus traffic as input (CLK, MISO, MOSI and CS signals).

### Analyzer settings

The `Trace` setting defines whether the analyzer decodes the data on MISO or MOSI. To fully decode SPI traffic, two analyzers must be added, one to decode MOSI and the second one to decode MISO.