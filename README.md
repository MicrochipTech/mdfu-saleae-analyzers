# Microchip Device Firmware Update (MDFU) Analyzers Extension for Saleae

This extension provides decoding capabilities for the Microchip Device Firmware Update (MDFU) protocol within the Saleae Logic Analyzer software. It allows users to capture, decode, and analyze MDFU traffic over various communication interfaces such as UART, SPI, and I2C. By leveraging this extension, developers and engineers can gain deeper insights into the firmware update process of Microchip devices, facilitating debugging and development tasks.

## Installation
### From Saleae Extension Marketplace

In the Saleae Logic Analyzer extension view menu first check for any updates by using `Check for Updates`, then search for `MDFU Analyzers` in the list of extensions and click on install.

### From Local Repository

1. **Clone or Download the Repository:**
   - Clone the repository using Git or download the ZIP file and extract it to your desired location.

2. **Load the Extension in Saleae:**
   - Open the Saleae Logic Analyzer software.
   - Access the extension settings from the side panel.
   - From the context menu, select `Load Existing Extension...`.
   - Navigate to the cloned or extracted repository and select the `extension.json` file located in the `MDFU_Analyzers` folder.

## Getting Started

1. **Capture MDFU Traffic:**
   - Use the Saleae Logic Analyzer to capture MDFU traffic on one of the supported transports, such as UART, SPI, or I2C.
   - Alternatively, you can open one of the sample captures available in the `capture` folder of the repository.

2. **Set up the Analyzer to decode Traffic:**
   - Detailed instructions for using the extension are available directly within the extension in the Saleae Logic Analyzer software.
   - The same information can also be obtained in the [README.md](MDFU_Analyzers/README.md) file in the `MDFU_Analyzers` folder of the repository.

3. **Analyze the Data:**
   - Use the decoded MDFU data to analyze the firmware update process.
   - The Saleae software will display the decoded MDFU protocol data, making it easier to understand and debug the firmware update process.

## Further information

For further assistance, refer to the following resources:
- [Microchip Device Firmware Update (MDFU) Protocol Documentation](https://microchip.com/DS50003743)
- [Saleae Logic Analyzer Documentation](https://support.saleae.com/)
