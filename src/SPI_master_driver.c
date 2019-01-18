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

#include "SPI_master_driver.h"


/*******************************
*    Variable Definitions      *
*******************************/
static uint64_t usec = 0;
int	spi_fd;
static const char *device = "/dev/spidev0.0";
static uint8_t mode = 1;
static uint8_t bits = 8;
static uint32_t speed = 1000000;
static uint16_t usdelay = 0;


/*******************************
*    Function Definitions      *
*******************************/
static void pabort(const char *s)
{
	perror(s);
	return;
}

//-------------------------------------------------------------------------
// Enable the adapter's power pins.
//-------------------------------------------------------------------------
void SPI_power_on(void){
    //not required for Raspberry Pi
}

//-------------------------------------------------------------------------
// Turn off the power pins.
//-------------------------------------------------------------------------
void SPI_power_off(void){
    //not required for Raspberry Pi
}

//-------------------------------------------------------------------------
// Open (Power up) the SPI interface
//-------------------------------------------------------------------------
void SPI_close_host_adapter()
{
    //not required for Raspberry Pi
}

//-------------------------------------------------------------------------
// Find host adapter, returns the number of the first adapter
//-------------------------------------------------------------------------
int SPI_find_host_adapters()
{
    //not required for Raspberry Pi
    return 0;
}


//-------------------------------------------------------------------------
// This function initialize the spi interface
// port is the spi channel to use, bitrate is spi clock.
//-------------------------------------------------------------------------
int SPI_init(int port, int bitrate)
{
    int ret;

    speed = bitrate*1000;
    spi_fd = open(device, O_RDWR);
    if (spi_fd < 0){
        LogError("can't open device /dev/spi*\n");
        goto errexit;
    }
    ret = ioctl(spi_fd, SPI_IOC_WR_MODE, &mode);
    if (ret == -1){
        LogError("can't set spi mode\n");
        goto errexit;
    }
    ret = ioctl(spi_fd, SPI_IOC_RD_MODE, &mode);
    if (ret == -1){
        LogError("can't get spi mode\n");
        goto errexit;
    }
    /*
     * bits per word
     */
    ret = ioctl(spi_fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
    if (ret == -1){
        LogError("can't set bits per word\n");
        goto errexit;
    }

    ret = ioctl(spi_fd, SPI_IOC_RD_BITS_PER_WORD, &bits);
    if (ret == -1){
        LogError("can't get bits per word\n");
        goto errexit;
    }

    /*
     * max speed hz
     */
    ret = ioctl(spi_fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);
    if (ret == -1){
        LogError("can't set max speed\n");
        goto errexit;
    }

    ret = ioctl(spi_fd, SPI_IOC_RD_MAX_SPEED_HZ, &speed);
    if (ret == -1){
        LogError("can't get max speed\n");
        goto errexit;
    }

    Log("[SPI settings: mode %d, %d bits, %d KHz]\n\n",
        mode, bits, speed/1000);

    return 1;
    errexit:
        LogError("SPI initialize failed\n");
	return 0;
}

//-------------------------------------------------------------------------
// Send a transaction via SPI, receive response
//-------------------------------------------------------------------------
int SPI_write (		   int numsent,
			   const BYTE *sendbuffer,
			   int numreceived,
			   BYTE *respbuffer)
{
   int ret;
    struct spi_ioc_transfer spi_tr = {
        .tx_buf = (unsigned long)sendbuffer,
        .rx_buf = (unsigned long)respbuffer,
        .len = numsent,
        .delay_usecs = usdelay,
        .speed_hz = speed,
        .bits_per_word = bits,
    };
#ifdef EMULATOR
    Sleep(1); //Increase stability for Emulator
#endif
    ret = ioctl(spi_fd, SPI_IOC_MESSAGE(1), &spi_tr);
    if (ret < 0){
        Log("SPI send err:%d\n",ret);
        return 0;
    }

    numreceived = numsent;
    return numsent;
}


// Function to reset the target.
// The parameter indicates reset type.
int32_t  SPI_Reset(uint32_t dwResetType){
    //not required for Raspberry Pi
    return 1;
}

// Function to set the device bit rate.
int32_t  SPI_SetBitRate(uint32_t dwBitRate){
    //not required for Raspberry Pi
    return 1;
}

