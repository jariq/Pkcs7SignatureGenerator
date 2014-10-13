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

namespace Pkcs7SignatureGenerator
{
    /// <summary>
    /// Hash algorithm
    /// </summary>
    public enum HashAlgorithm
    {
        /// <summary>
        /// The SHA1 hash algorithm
        /// </summary>
        SHA1,

        /// <summary>
        /// The SHA256 hash algorithm
        /// </summary>
        SHA256,

        /// <summary>
        /// The SHA384 hash algorithm
        /// </summary>
        SHA384,

        /// <summary>
        /// The SHA512 hash algorithm
        /// </summary>
        SHA512
    }
}
