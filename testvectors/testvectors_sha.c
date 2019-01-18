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

// -----------------------------------------------------------------------------------------------------
// SHA256 test vector
// -----------------------------------------------------------------------------------------------------
char *TestVector_SHA_Message[]= {"d3", // 1 byte
                                 "5738c929c4f4ccb6", // 8 bytes
                                 "0a27847cdc98bd6f62220b046edd762b", // 16 bytes
                                 "09fc1accc230a205e4a208e64a8f204291f581a12756392da4b8c0cf5ef02b95",   // 32 bytes
                                 "0546f7b8682b5b95fd32385faf25854cb3f7b40cc8fa229fbd52b16934aab388a7", // 33 bytes
                                 "4e3d8ac36d61d9e51480831155b253b37969fe7ef49db3b39926f3a00b69a36774366000" //36 bytes
};
char *TestVector_SHA_Out[]    = {"28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1",
                                 "963bb88f27f512777aab6c8b1a02c70ec0ad651d428f870036e1917120fb48bf",
                                 "80c25ec1600587e7f28b18b1b18e3cdc89928e39cab3bc25e4d4a4c139bcedc4",
                                 "4f44c1c7fbebb6f9601829f3897bfd650c56fa07844be76489076356ac1886a4",
                                 "b31ad3cd02b10db282b3576c059b746fb24ca6f09fef69402dc90ece7421cbb7",
                                 "bf9d5e5b5393053f055b380baed7e792ae85ad37c0ada5fd4519542ccc461cf3"
};
