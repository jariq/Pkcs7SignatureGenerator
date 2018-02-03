/*
 *  Pkcs7SignatureGenerator
 *  Example application for PKCS#7 signature creation with Pkcs11Interop and BouncyCastle libraries
 *  Copyright (c) 2014 JWC s.r.o. <http://www.jwc.sk>
 *  Author: Jaroslav Imrich <jimrich@jimrich.sk>
 *
 *  Licensing for open source projects:
 *  Pkcs7SignatureGenerator is available under the terms of the GNU Affero General 
 *  Public License version 3 as published by the Free Software Foundation.
 *  Please see <http://www.gnu.org/licenses/agpl-3.0.html> for more details.
 *
 *  Licensing for other types of projects:
 *  Pkcs7SignatureGenerator is available under the terms of flexible commercial license.
 *  Please contact JWC s.r.o. at <info@pkcs11interop.net> for more details.
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
