/* MIT License
 * 
 * Pkcs7SignatureGenerator - Sample application for PKCS#7/CMS/SMIME signature 
 * creation with Pkcs11Interop, BouncyCastle and MimeKit libraries.
 * 
 * Copyright (c) 2014-2025 Jaroslav Imrich <jimrich@jimrich.sk>
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

using System;

namespace Pkcs7SignatureGenerator
{
    /// <summary>
    /// Known OIDs
    /// </summary>
    public static class OID
    {
        /// <summary>
        /// PKCS#9 contentType attribute
        /// </summary>
        public static string PKCS9AtContentType = "1.2.840.113549.1.9.3";

        /// <summary>
        /// PKCS#9 messageDigest attribute
        /// </summary>
        public static string PKCS9AtMessageDigest = "1.2.840.113549.1.9.4";

        /// <summary>
        /// PKCS#9 signingTime attribute
        /// </summary>
        public static string PKCS9AtSigningTime = "1.2.840.113549.1.9.5";

        /// <summary>
        /// PKCS#1 RSAES-PKCS-v1_5 signature scheme
        /// </summary>
        public static string PKCS1RsaEncryption = "1.2.840.113549.1.1.1";

        /// <summary>
        /// PKCS#1 RSASSA-PSS signature scheme
        /// </summary>
        public static string PKCS1RsassaPss = "1.2.840.113549.1.1.10";

        /// <summary>
        /// PKCS#1 MGF1 mask generation function
        /// </summary>
        public static string PKCS1Mgf1 = "1.2.840.113549.1.1.8";

        /// <summary>
        /// PKCS#7 data content type
        /// </summary>
        public static string PKCS7IdData = "1.2.840.113549.1.7.1";

        /// <summary>
        /// PKCS#7 signed-data content type
        /// </summary>
        public static string PKCS7IdSignedData = "1.2.840.113549.1.7.2";

        /// <summary>
        /// The SHA1 hash algorithm
        /// </summary>
        public static string SHA1 = "1.3.14.3.2.26";

        /// <summary>
        /// The SHA256 hash algorithm
        /// </summary>
        public static string SHA256 = "2.16.840.1.101.3.4.2.1";

        /// <summary>
        /// The SHA384 hash algorithm
        /// </summary>
        public static string SHA384 = "2.16.840.1.101.3.4.2.2";

        /// <summary>
        /// The SHA512 hash algorithm
        /// </summary>
        public static string SHA512 = "2.16.840.1.101.3.4.2.3";
    }
}
