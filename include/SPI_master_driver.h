/*
* MIT License
*
* Copyright (c) 2019 Infineon Technologies AG
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

#ifndef SPI_MASTER_DRIVER_H_
#define SPI_MASTER_DRIVER_H_

/*******************************
*    Includes                  *
*******************************/

#include "common.h"

#include <linux/spi/spidev.h>
#include <sys/ioctl.h>


/*******************************
*    Data Types and Variables  *
*******************************/


/*******************************
*    Function Declarations     *
*******************************/

// This function initialize the spi interface:
int SPI_init(int port, int bitrate);

//Function to exchange a data blob over SPI interface:
int SPI_write (int numsent,
               const BYTE *sendbuffer,
               int numreceived,
               BYTE *respbuffer);




// Not used for Raspberry Pi:
void SPI_power_on(void);
void SPI_power_off(void);
int SPI_find_host_adapters(void);
void SPI_close_host_adapter();
int32_t  SPI_Reset(uint32_t dwResetType); //Function to reset the target. The parameter indicates reset type.
int32_t  SPI_SetBitRate(uint32_t dwBitRate); //Function to set the device bit rate.


#endif /* SPI_MASTER_DRIVER_H_ */


