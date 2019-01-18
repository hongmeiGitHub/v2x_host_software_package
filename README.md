# Infineon V2X Host Software Package

## Description
This repository contains the host software for the Infineon SLS37 V2X Prototype security controller.

## Summary
The Infineon SLS37 V2X Prototype is a prototype of an SPI hardware security module (HSM) for the Vehicle-to-Everything (V2X) market. Its main task is signature generation for V2X messages and secure key storage. The V2X Host Software Package repository contains the corresponding host-side software and can be used as a reference for speeding up the integration of the Infineon SLS37 V2X Prototype API into a V2X stack running on an embedded V2X host system (e.g. a telematic box). The V2X Host Software Package is meant to be run on a Raspberry Pi with Raspbian OS. Infineon does not provide any kind of warranty for this demo code.

## Key Features of the V2X Host Software Package
* Exemplary SPI Driver and Protocol implementation
* Exemplary SLS37 V2X Prototype API implementation
* Demo and test utility ('v2xtool' command line interpreter)

## Required Hardware
* Raspberry Pi Model 3 with Raspbian OS
* Infineon SLS37 V2X Prototype Solution ([email us](mailto:dsscustomerservice@infineon.com))
    * SLS37 V2X Prototype sample IC
    * SLS37 V2X Prototype Databook

## Get Started
1. Get the Infineon SLS37 V2X Prototype Solution containing a sample IC and detailed technical documentation ([email us](mailto:dsscustomerservice@infineon.com))
2. Connect SPI and power lines with your Raspberry Pi
3. Make sure, openSSL is installed on your Raspberry Pi
4. Compile the V2X Host Software Package by running the Makefile
5. Run the 'v2xtool' executable and type 'help' for a list of all available commands

## Overview

<img width="800" src="https://raw.githubusercontent.com/Infineon/v2x_host_software_package/master/overview.png">

The V2X Host Software Package consists of the following building blocks:

##### SPI Master Driver
* This module implements an interface to the /dev/spidev0.0 device file for reading and writing raw bytes via SPI.

##### SLS37 V2X Prototype SPI Protocol
* The SPI Protocol implements the Data Link layer. It is responsible for the mapping of ISO 7816 APDUs into an SPI frame and securing the transmission.

##### SLS37 V2X Prototype API
* The SLS37 V2X Prototype API is the main interface for an end user. It contains a rich set of functions, the SLS37 V2X Prototype provides.

##### V2X Tool
* The V2X Tool is a basic command line interpreter for running cryptographic test vectors, stability and speed tests and for performing firmware updates. It can be also used as a reference for how to use the API implementation.

##### Crypto Wrapper
* The Crypto Wrapper is an abstraction layer for host side cryptographic operations. In this implementation, the openSSL library is used. If another cryptographic library shall be used, the Crypto Wrapper has to be modified accordingly.

## Documentation
Detailed documentation can be found in the SLS37 V2X Prototype Databook, which is part of the Infineon SLS37 V2X Prototype Solution. Please [email us](mailto:dsscustomerservice@infineon.com) to get the required hardware and documentation.

## Porting Guide
The Infineon V2X Host Software Package is meant to be run a Raspberry Pi Model 3 with Raspbian OS or any similar Linux system with access to the SPI interface via a device file (e.g. /dev/spidev0.0). The code has been tested with Raspbian GNU/Linux 9 (stretch) Kernel version 4.14.


## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## License
This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
