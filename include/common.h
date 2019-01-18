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

#ifndef COMMON_H
#define COMMON_H


/*******************************
*    Includes                  *
*******************************/
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h> //for gettimeofday()
#include <stdint.h>

/*******************************
*    Defines/Macros            *
*******************************/

#define DEBUG

#define USEPERFORMANCECOUNTER

#define LOG_FILENAME    "V2X_SPI.log"
#define _stat stat
#define _access access

#define LONGLONG uint64_t
#define MAX_COMMAND_HISTORY 50
#define PASSWORD_PROMPT "Please enter key file encryption password: "

#define TRUE 1
#define FALSE 0

#define DIGEST_SIZE 32 //following values are hardcoded for SHA256 / ECC256
#define ECDH_SIZE 32

#define AES128_KEY_SIZE 16
#define AES256_KEY_SIZE 32

#define ECIES_TAG_SIZE 16

#define ECC_PRIV_KEY_SIZE 32
#define ECC_PUB_KEY_SIZE 65
#define ECC_COORD_SIZE ECC_PRIV_KEY_SIZE
#define SIGNATURE_SIZE 65

#define SESSION_ENC_ALG ALG_AES_256
#define SESSION_ENC_MODE CRYPT_MODE_CBC
#define SESSION_KEY_SIZE AES256_KEY_SIZE
#define MAC_SIZE 16

#define BUFFER_SIZE  2048
#define MAX_APDU_SIZE 1800
#define MAX_DATA_SIZE MAX_APDU_SIZE-40

#define LogError LogScreen
#define SAFE_FREE(x) if (x) free(x); x=NULL;
#define SAFE_MALLOC(var,size) if ((var=(unsigned char *) malloc(size)) == NULL) { exit(1); }
#define BIG_ENDIAN_LONG(x) (x)[0]*16777216 + (x)[1]*65536 + (x)[2]*256 + (x)[3]
#define BIG_ENDIAN_3(x)                      (x)[0]*65536 + (x)[1]*256 + (x)[2]
#define BIG_ENDIAN_WORD(x)                                  (x)[0]*256 + (x)[1]
#define LITTLE_ENDIAN_LONG(x) (x)[3]*16777216 + (x)[2]*65536 + (x)[1]*256 + (x)[0]
#define LITTLE_ENDIAN_WORD(x) (x)[1]*256 + (x)[0]


#define CMD(apdu,sw) APDU(apdu); \
                     if (SW1SW2 != sw) { \
                        errorflag = 1; \
                        LogError("ERROR: APDU: %s, SW1SW2: %04X, expected: %04X\n", apdu, SW1SW2, sw); \
                        break; \
                     }

/*******************************
*    Data Types and Variables  *
*******************************/
typedef enum _RETURN_CODE {
	RES_OK = 0,
	RES_ERROR = -1,
	RES_ABORTED = -2,
	RES_EOF = -3,
	RES_UNDEFINED = -4,
	RES_VENDOR_ERROR = -5,
	RES_WARNING = -6  } RETURN_CODE;
typedef struct {
	char command[256];
	char comment[256];
} command_structure;
extern char LogFileName[];
extern int LogLevel;
extern int LogLevelFile;
LONGLONG Stat_Time_start, Stat_Time_finish;
typedef int BOOL;
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef float FLOAT;
typedef unsigned short UINT16;

/*******************************
*    Function Declarations     *
*******************************/
int LogScreen(char *format, ...);
int Log(char *format, ...);
int LogPort(char *format, ...);
int LogAll(char *format, ...);
void DumpLine(int loglevel, int addr, BYTE *hexdata, int len);
void StrDump(char * message, BYTE *data, int len);
void HexDump(char * message, BYTE *data, int len);
void HexDumpPort(char * message, BYTE *data, int len);
char *HexStringNoSpace(BYTE *data, int num, char *dest);
int FileExists(char * filename);
BYTE* LoadFromFile(char *fname, BYTE *data, int *len);
int SaveToFile(char *fname, BYTE *data, int len);
int CompareBuffers(BYTE *buf1, BYTE *buf2, int len1, int len2);
void clrscr(void);
short checkKey(void);
short getKey(void);
void Sleep(int time);
void Xor (BYTE*  pbInBuffer, BYTE*  pbOutBuffer, uint32_t InputDataLen);
void Big_Endian(int x, BYTE *arr);
int UTIL_hexStrToArray(char *str, BYTE *res, int maxsize);
short CalcCRC16(unsigned char *data, int len);
LONGLONG GetTimerValue(void);
FILE *openFile(char *filename);
int readLineFromFile(FILE *stream, char *data, int maxlen);
void closeFile(FILE *stream);
int Ask_Password(char *prompt, char *password);
int SaveToFile(char *fname, BYTE *data, int len);
char * stringRemoveChars(char *string, char *spanset);
int parse_comments(char* buffer, command_structure* defs, int maxdefs);
int read_file(char* filename, char ** ptr);



#endif
