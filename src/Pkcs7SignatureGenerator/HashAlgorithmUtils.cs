/* MIT License
 * 
 * Pkcs7SignatureGenerator - Sample application for PKCS#7/CMS/SMIME signature 
 * creation with Pkcs11Interop, BouncyCastle and MimeKit libraries.
 * 
 * Copyright (c) 2014-2024 Jaroslav Imrich <jimrich@jimrich.sk>
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
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Pkcs7SignatureGenerator
{
    /// <summary>
    /// Utility class for HashAlgorithm enum
    /// </summary>
    public static class HashAlgorithmUtils
    {
        /// <summary>
        /// Returns value of micalg (Message Integrity Check Algorithm) parameter for specified hash algorithm as defined in RFC 5751 section 3.4.3.2
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm</param>
        /// <returns>Value of micalg parameter for specified hash algorithm</returns>
        public static string GetHashMicalgName(HashAlgorithm hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
                case HashAlgorithm.SHA1:
                    return "sha-1";
                case HashAlgorithm.SHA256:
                    return "sha-256";
                case HashAlgorithm.SHA384:
                    return "sha-384";
                case HashAlgorithm.SHA512:
                    return "sha-512";
                default:
                    throw new NotSupportedException("Unsupported hash algorithm");
            }
        }

        /// <summary>
        /// Returns OID of specified hash algorithm
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm</param>
        /// <returns>OID of specified hash algorithm</returns>
        public static string GetHashOid(HashAlgorithm hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
                case HashAlgorithm.SHA1:
                    return OID.SHA1;
                case HashAlgorithm.SHA256:
                    return OID.SHA256;
                case HashAlgorithm.SHA384:
                    return OID.SHA384;
                case HashAlgorithm.SHA512:
                    return OID.SHA512;
                default:
                    throw new NotSupportedException("Unsupported hash algorithm");
            }
        }

        /// <summary>
        /// Returns implementation of specified hash algorithm
        /// </summary>
        /// <param name="hashAlgorithm">Hash algorithm</param>
        /// <returns>Implementation of specified hash algorithm</returns>
        public static IDigest GetHashGenerator(HashAlgorithm hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
                case HashAlgorithm.SHA1:
                    return new Sha1Digest();
                case HashAlgorithm.SHA256:
                    return new Sha256Digest();
                case HashAlgorithm.SHA384:
                    return new Sha384Digest();
                case HashAlgorithm.SHA512:
                    return new Sha512Digest();
                default:
                    throw new NotSupportedException("Unsupported hash algorithm");
            }
        }
    }
}
