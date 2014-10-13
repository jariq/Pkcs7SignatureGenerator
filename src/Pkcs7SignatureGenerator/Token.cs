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
using Net.Pkcs11Interop.HighLevelAPI;

namespace Pkcs7SignatureGenerator
{
    /// <summary>
    /// PKCS#11 token (smartcard)
    /// </summary>
    public class Token
    {
        /// <summary>
        /// PKCS#11 slot
        /// </summary>
        internal Slot Slot = null;

        /// <summary>
        /// Token manufacturer
        /// </summary>
        private string _manufacturerId = null;

        /// <summary>
        /// Token manufacturer
        /// </summary>
        public string ManufacturerId
        {
            get
            {
                return _manufacturerId;
            }
        }

        /// <summary>
        /// Token model
        /// </summary>
        private string _model = null;

        /// <summary>
        /// Token model
        /// </summary>
        public string Model
        {
            get
            {
                return _model;
            }
        }

        /// <summary>
        /// Token serial number
        /// </summary>
        private string _serialNumber = null;

        /// <summary>
        /// Token serial number
        /// </summary>
        public string SerialNumber
        {
            get
            {
                return _serialNumber;
            }
        }

        /// <summary>
        /// Token label
        /// </summary>
        private string _label = null;

        /// <summary>
        /// Token label
        /// </summary>
        public string Label
        {
            get
            {
                return _label;
            }
        }

        /// <summary>
        /// Intitializes class instance
        /// </summary>
        /// <param name="slot">PKCS#11 slot</param>
        /// <param name="manufacturerId">Token manufacturer</param>
        /// <param name="model">Token model</param>
        /// <param name="serialNumber">Token serial number</param>
        /// <param name="label">Token label</param>
        internal Token(Slot slot, string manufacturerId, string model, string serialNumber, string label)
        {
            if (slot == null)
                throw new ArgumentNullException("slot");

            Slot = slot;
            _manufacturerId = manufacturerId;
            _model = model;
            _serialNumber = serialNumber;
            _label = label;
        }
    }
}
