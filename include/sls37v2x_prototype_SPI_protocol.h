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

#ifndef V2X_PROTOTYPE_SPI_PROTOCOL_H
#define V2X_PROTOTYPE_SPI_PROTOCOL_H


/*******************************
*    Includes                  *
*******************************/
#include "SPI_master_driver.h"
#include "common.h"

/*******************************
*    Defines/Macros            *
*******************************/
#define SLEEP_TIME 1


#define SPI_BITRATE  120000
#define MAX_APDU_TRIES 3

#define SPI_PROTOCOL_HEADER_LENGTH 4
#define SPI_PROTOCOL_MIN_PACKET_LENGTH (SPI_PROTOCOL_HEADER_LENGTH + 4)
#define SPI_PROTOCOL_MAX_PACKET_LENGTH 16

#define SPI_PROTOCOL_REQUEST_HEADER  0x7E
#define SPI_PROTOCOL_REQUEST_NOCHAIN  0x80
#define SPI_PROTOCOL_REQUEST_CHAINING 0x90

#define SPI_PROTOCOL_RESPONSE_HEADER 0x7E
#define SPI_PROTOCOL_RESPONSE_STATUS_OK_NOCHAIN 0x00
#define SPI_PROTOCOL_RESPONSE_STATUS_OK_CHAIN   0x10
#define SPI_PROTOCOL_RESPONSE_STATUS_ERROR      0x80


/*******************************
*    Data Types and Variables  *
*******************************/
extern int Log_Timing;
static BYTE zerobuffer[BUFFER_SIZE*2];
LONGLONG Stat_Time_start, Stat_Time_finish;


/*******************************
*    Function Declarations     *
*******************************/
int	SPI_protocol_init(int bitrate);
void	SPI_protocol_close();

void	SPI_protocol_reset(void);

int		SPI_protocol_send (BYTE *apdu, 
                   int apdulen, 
                   BYTE *response,
                   int *respsize,
                   int maxtries,
                   int timeout);


#endif
