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
    /// Exception indicating that requested token was not found
    /// </summary>
    public class TokenNotFoundException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the TokenNotFoundException class
        /// </summary>
        public TokenNotFoundException()
            : base()
        {

        }

        /// <summary>
        /// Initializes a new instance of the TokenNotFoundException class with a specified error message
        /// </summary>
        /// <param name="message">The message that describes the error</param>
        public TokenNotFoundException(string message)
            : base(message)
        {

        }

        /// <summary>
        /// Initializes a new instance of the TokenNotFoundException class with a specified error message and a reference to the inner exception that is the cause of this exception
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception</param>
        /// <param name="innerException">The exception that is the cause of the current exception, or a null reference if no inner exception is specified.</param>
        public TokenNotFoundException(string message, Exception innerException)
            : base(message, innerException)
        {

        }
    }
}
