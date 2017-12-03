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
    /// RSA signature schemes defined in RFC 8017
    /// </summary>
    public enum SignatureScheme
    {
        /// <summary>
        /// RSASSA-PKCS1-v1_5 scheme
        /// </summary>
        RSASSA_PKCS1_v1_5,

        /// <summary>
        /// RSASSA-PSS scheme
        /// </summary>
        RSASSA_PSS
    }
}
