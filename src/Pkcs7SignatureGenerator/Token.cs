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
