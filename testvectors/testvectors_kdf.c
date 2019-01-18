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
// KDF2 test vectors ANSI X9.63
// -----------------------------------------------------------------------------------------------------
BYTE *TestVector_KDF2_SS[]  = {"96c05619d56c328ab95fe84b18264b08725b85e33fd34f08",
                               "96f600b73ad6ac5629577eced51743dd2c24c21b1ac83ee4",
                               "22518b10e70f2a3f243810ae3254139efbee04aa57c7af7d",
                               "7e335afa4b31d772c0635c7b0e06f26fcd781df947d2990a"
};
BYTE *TestVector_KDF2_KDP[] = {"",
                               "",
                               "75eef81aa3041e33b80971203d2c0c52",
                               "d65a4812733f8cdbcdfb4b2f4c191d87"
};
int TestVector_KDF2_Len[] = {16,
                             16,
                             32, // 128
                             32  // 128
};
BYTE *TestVector_KDF2_Out[] = {"443024c3dae66b95e6f5670601558f71",
                               "b6295162a7804f5667ba9070f82fa522",
                               "c498af77161cc59f2962b9a713e2b215152d139766ce34a776df11866a69bf2e", // 52a13d9c7c6fc878c50c5ea0bc7b00e0da2447cfd874f6cf92f30d0097111485500c90c3af8b487872d04685d14c8d1dc8d7fa08beb0ce0ababc11f0bd496269142d43525a78e5bc79a17f59676a5706dc54d54d4d1f0bd7e386128ec26afc21",
                               "c0bd9e38a8f9de14c2acd35b2f3410c6988cf02400543631e0d6a4c1d030365a"  // cbf398115e51aaddebdc9590664210f9aa9fed770d4c57edeafa0b8c14f93300865251218c262d63dadc47dfa0e0284826793985137e0a544ec80abf2fdf5ab90bdaea66204012efe34971dc431d625cd9a329b8217cc8fd0d9f02b13f2f6b0b"
};
