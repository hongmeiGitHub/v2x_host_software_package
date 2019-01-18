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

#include "sls37v2x_prototype_SPI_protocol.h"

/*******************************
*    Variable Definitions      *
*******************************/
static BYTE Current_PCB = 0x80;
int Log_Timing = 0;



/*******************************
*    Function Definitions      *
*******************************/

//-------------------------------------------------------------------------
// Open and configure SPI host adapter
// Returns 1 in case of success or 0 in case of initialization failure
//-------------------------------------------------------------------------
int SPI_protocol_init(int bitrate)
{
    int port  = 0;
    memset(zerobuffer, 0xFF, sizeof(zerobuffer));

    // Find first SPI host adapter
    port = SPI_find_host_adapters();
    if (port < 0) {
#ifdef DEBUG
        LogError("No SPI adapter found !!!\n");
#endif
        return 0;
    }
    // Open and configure SPI host adapter
    if (SPI_init(port, bitrate) == 0) {
#ifdef DEBUG
        LogError("SPI adapter initialization error !!!\n");
#endif
        return 0;
    }
    return 1;
}

//-------------------------------------------------------------------------
// Close SPI host adapter
//-------------------------------------------------------------------------
void SPI_protocol_close()
{
    SPI_close_host_adapter();
}

//-------------------------------------------------------------------------
// Resets SPI slave device by sending "reset" sequence 2048 zero bytes
//-------------------------------------------------------------------------
void SPI_protocol_reset(void)
{
    int i;
    BYTE sendbuffer[SPI_PROTOCOL_MAX_PACKET_LENGTH];
    BYTE dummybuffer[SPI_PROTOCOL_MAX_PACKET_LENGTH];

    memset(sendbuffer, 0, SPI_PROTOCOL_MAX_PACKET_LENGTH);

    // -------------------- Send 2048 + 16 zero bytes to SPI slave ------------------
    for (i=0; i < BUFFER_SIZE; i+=SPI_PROTOCOL_MAX_PACKET_LENGTH) {
	    SPI_write(SPI_PROTOCOL_MAX_PACKET_LENGTH, sendbuffer, SPI_PROTOCOL_MAX_PACKET_LENGTH, dummybuffer);
        Sleep(SLEEP_TIME);
    }
    SPI_write(8, sendbuffer, 8, dummybuffer);
}

//-------------------------------------------------------------------------
// Send APDU over SPI using Infineon SPI protocol (HDLC with byte stuffing)
// Returns 1 in case of success or 0 in case of packet transmission failure
//-------------------------------------------------------------------------
int SPI_protocol_send (BYTE *apdu,
                       int apdulen,
                       BYTE *response,
                       int *respsize,
                       int maxtries,
                       int timeout)
{
    BYTE sendbuffer[BUFFER_SIZE];
    BYTE sendbufferstuffed[BUFFER_SIZE*2];
    BYTE respbuffer[BUFFER_SIZE];
    BYTE dummybuffer[BUFFER_SIZE];
    int numsent = 0, numsentstuffed, buf_offset, buf_len, resplen = 0, trycounter = maxtries;
    int start, i, firstblocksize, secondblocksize, ret = 0;
    WORD crc;
	int timecnt;

    *respsize = 0;

    memset(sendbuffer, 0, BUFFER_SIZE);
    sendbuffer[numsent++] = SPI_PROTOCOL_REQUEST_HEADER;
    sendbuffer[numsent++] = Current_PCB;
    sendbuffer[numsent++] = (BYTE)((apdulen >> 8) & 0xFF);
    sendbuffer[numsent++] = (BYTE)(apdulen & 0xFF);
    memcpy(sendbuffer+numsent, apdu, apdulen);
    numsent += apdulen;
    crc = CalcCRC16(sendbuffer, numsent);
    sendbuffer[numsent++] = (BYTE)((crc >> 8) & 0xFF);
    sendbuffer[numsent++] = (BYTE)(crc & 0xFF);

#ifdef DEBUG
    if (LogLevel > 1 || LogLevelFile > 1) HexDumpPort("Send: ", apdu, apdulen); //sendbuffer, numsent);
#endif
    //---------------------Byte stuffing: change 7E -> 7D 5E, 7D -> 7D 5D------------------------------
    sendbufferstuffed[0] = SPI_PROTOCOL_REQUEST_HEADER;
    for (numsentstuffed=1, i=1; i < numsent; i++) {
        if      (sendbuffer[i] == 0x7E) { sendbufferstuffed[numsentstuffed++] = 0x7D; sendbufferstuffed[numsentstuffed++] = 0x5E; }
        else if (sendbuffer[i] == 0x7D) { sendbufferstuffed[numsentstuffed++] = 0x7D; sendbufferstuffed[numsentstuffed++] = 0x5D; }
        else                              sendbufferstuffed[numsentstuffed++] = sendbuffer[i];
    }
    Stat_Time_start = GetTimerValue();
    Sleep(1); //Increase stability

   while (1)
    {
#ifdef DEBUG
        if (LogLevel > 2 || LogLevelFile > 2) HexDumpPort("  --> ", sendbufferstuffed, numsentstuffed);
#endif
        // -------------------- Send APDU to SPI slave ------------------------
        buf_offset = 0;
        buf_len = numsentstuffed;
        while (buf_len > 0) {
            if (buf_len > SPI_PROTOCOL_MAX_PACKET_LENGTH) numsent = SPI_PROTOCOL_MAX_PACKET_LENGTH;
            else                                          numsent = buf_len;

    	    SPI_write(numsent, sendbufferstuffed + buf_offset, numsent, dummybuffer);
            buf_offset += numsent;
            buf_len -= numsent;
            Sleep(SLEEP_TIME); //UA
        }
        //---------------------------------------------------------------------

#ifdef DEBUG
        if (LogLevel > 2 || LogLevelFile > 2) // Deep protocol debug mode
            LogAll("  <-- ");
#endif
        // ---------- Wait for the header received from SPI slave --------------
        firstblocksize = SPI_PROTOCOL_MIN_PACKET_LENGTH; // 8
        timecnt = 0;
        do {
		    SPI_write(firstblocksize, zerobuffer, firstblocksize, respbuffer);
	//---------------------------------------------------------------------
            start = -1;
            for (i=0; i < firstblocksize; i++) {
                if (respbuffer[i] == SPI_PROTOCOL_RESPONSE_HEADER) { start = i; break; }
#ifdef DEBUG
                if (LogLevel > 2 || LogLevelFile > 2) LogAll("%02X ", respbuffer[i]); // Deep protocol debug mode
#endif
		    }
            if (start >= 0) break;
#ifdef EMULATOR
            Sleep(10); //Poll less frequently. Increases stability for emulator
#else
            Sleep(1);
#endif
            if (++timecnt > timeout * 10) {
#ifdef DEBUG
                Log("\n");
                if (LogLevel == 1 || LogLevelFile == 1) {
                    HexDump("  --> ", sendbufferstuffed, numsentstuffed);
                }
			    Log("Stuck in loop waiting for response header...retrying\n");
    		    // DEBUG CODE - Added to trigger on packet exchange failure using scope
//			    SPI_WRITE_TEST(); // Make an SS pulse for oscilloscope debugging
#endif
			    goto retry_label;
		    }
        } while (start < 0);

        // ---------- Receive the rest of the packet from SPI slave --------------
        secondblocksize = 0;
        if (start > firstblocksize - SPI_PROTOCOL_HEADER_LENGTH)
        {
		    secondblocksize = start + SPI_PROTOCOL_HEADER_LENGTH - firstblocksize;

		    SPI_write(secondblocksize, zerobuffer, secondblocksize, respbuffer + firstblocksize);
		Sleep(SLEEP_TIME);	//UA
	//---------------------------------------------------------------------
#ifdef DEBUG
            if (LogLevel > 2 || LogLevelFile > 2) // Deep protocol debug mode
                for (i=0; i < secondblocksize; i++)
                    LogAll("%02X ", respbuffer[firstblocksize + i]);
#endif
        }
        firstblocksize = firstblocksize + secondblocksize - start;
        memmove(respbuffer, respbuffer+start, firstblocksize);

        if (respbuffer[1] == SPI_PROTOCOL_RESPONSE_STATUS_ERROR+1) {
#ifdef DEBUG
            Log("\nERROR: Chip reported CRC error (status=0x81):\n");
#endif
            goto retry_label;
        }
        resplen = respbuffer[2] * 256 + respbuffer[3];
        if (resplen > BUFFER_SIZE) {
#ifdef DEBUG
            Log("\nERROR: Wrong response length: %d bytes (exceeds buffer size %d)\n", resplen, BUFFER_SIZE); 
#endif
            goto retry_label;
        }
        *respsize = resplen;

        // ----------- Receive the rest of the packet (data, CRC16) ------------
        if (resplen > 0) {
            buf_offset = firstblocksize;
            buf_len = resplen+2+start-SPI_PROTOCOL_HEADER_LENGTH;
            while (buf_len > 0) {
                if (buf_len > SPI_PROTOCOL_MAX_PACKET_LENGTH) numsent = SPI_PROTOCOL_MAX_PACKET_LENGTH;
                else                                          numsent = buf_len;
                SPI_write(numsent, zerobuffer,
                          numsent, respbuffer + buf_offset);
                buf_offset += numsent;
                buf_len -= numsent;
            }
	    }
#ifdef DEBUG
        if (LogLevel > 2 || LogLevelFile > 2) {
            LogPort("\n");
            HexDumpPort("  <-- ", respbuffer, resplen+6);
        }
#endif
        Stat_Time_finish = GetTimerValue();

#ifdef DEBUG
        if (LogLevel > 1 || LogLevelFile > 1) HexDumpPort("Recv: ", respbuffer+4, resplen); // respbuffer, resplen+6);
#endif
        memcpy(response, respbuffer+4, resplen);

        crc = CalcCRC16(respbuffer, resplen+4);         // Check packet CRC starting from the header
        if ((BYTE)((crc >> 8) & 0xFF) == respbuffer[4+resplen] &&
            (BYTE)(crc & 0xFF)        == respbuffer[4+resplen+1])
        {
            ret = 1;
            goto spi_exit;
        }
#ifdef DEBUG
        Log("\nERROR: Wrong response CRC: calculated: %04X, received %02X%02X\n",
                             crc, respbuffer[4+resplen], respbuffer[4+resplen+1]);
#endif
retry_label:
        if (--trycounter <= 0) break;
    }
spi_exit:
#ifdef DEBUG
    if (LogLevel > 2 || LogLevelFile > 2) LogAll("\n");
    if (LogLevel > 1 || LogLevelFile > 1 || Log_Timing) LogPort("Time: %8d ms\n", (unsigned int)(Stat_Time_finish - Stat_Time_start)); 
    if (LogLevel > 2 || LogLevelFile > 2) LogAll("\n");
#endif
    return ret;
}
