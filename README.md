# Microchip Device Firmware Update (MDFU) analyzers extension for Saleae

## Linting

Run pylint and pass in the analyzer directory to get a linting report e.g. `pylint --recursive=y .\MDFU_SPI_Transport_Analyzer\`. The recursive flag is a workaround since we don't have a Python package here in the directory (we dont have the `__init__.py` file which pylint expects).