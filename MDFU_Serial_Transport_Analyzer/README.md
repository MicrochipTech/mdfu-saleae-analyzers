# MDFU UART transport analyzer Saleae extension


## Getting started

The Microchip Device Firmware Update (MDFU) UART transport analyzer decodes serial traffic and enables an in depth view of the protocol.

The analyzer requires a valid capture of the serial traffic as input (RX, TX).

## Analyzer settings

The `Trace` setting defines whether the analyzer decodes the data on RX or TX. To fully decode serial traffic, two analyzers must be added, one to decode TX and the second one to decode RX.