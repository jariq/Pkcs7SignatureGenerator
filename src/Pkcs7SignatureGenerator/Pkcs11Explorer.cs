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
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace Pkcs7SignatureGenerator
{
    /// <summary>
    /// Explores devices accessible via PKCS#11 interface
    /// </summary>
    public class Pkcs11Explorer : IDisposable
    {
        /// <summary>
        /// Flag indicating whether instance has been disposed
        /// </summary>
        private bool _disposed = false;

        /// <summary>
        /// High level PKCS#11 wrapper
        /// </summary>
        private Pkcs11 _pkcs11 = null;

        /// <summary>
        /// Initializes a new instance of the Pkcs11Explorer class
        /// </summary>
        /// <param name="libraryPath">Path to the unmanaged PCKS#11 library</param>
        public Pkcs11Explorer(string libraryPath)
        {
            if (string.IsNullOrEmpty(libraryPath))
                throw new ArgumentNullException("libraryPath");

            _pkcs11 = new Pkcs11(libraryPath, AppType.MultiThreaded);
        }

        /// <summary>
        /// Gets list of tokens (smartcards) accessible via PKCS#11 interface
        /// </summary>
        /// <returns></returns>
        public List<Token> GetTokens()
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            List<Token> tokens = new List<Token>();

            List<Slot> slots = _pkcs11.GetSlotList(SlotsType.WithTokenPresent);
            foreach (Slot slot in slots)
            {
                TokenInfo tokenInfo = null;

                try
                {
                    tokenInfo = slot.GetTokenInfo();
                }
                catch (Pkcs11Exception ex)
                {
                    if (ex.RV != CKR.CKR_TOKEN_NOT_RECOGNIZED && ex.RV != CKR.CKR_TOKEN_NOT_PRESENT)
                        throw;
                }

                if (tokenInfo != null)
                    tokens.Add(new Token(slot, tokenInfo.ManufacturerId, tokenInfo.Model, tokenInfo.SerialNumber, tokenInfo.Label));
            }

            return tokens;
        }

        /// <summary>
        /// Gets private keys and certificates stored in token (smartcard) accessible via PKCS#11 interface
        /// </summary>
        /// <param name="token">PKCS#11 token (smartcard) that should be explored</param>
        /// <param name="login">Flag indicating whether token login with provided PIN should be performed</param>
        /// <param name="pin">PIN for the token (smartcard)</param>
        /// <param name="privateKeys">List of private keys stored in token (smartcard)</param>
        /// <param name="certificates">List of certificates stored in token (smartcard)</param>
        public void GetTokenObjects(Token token, bool login, string pin, out List<PrivateKey> privateKeys, out List<Certificate> certificates)
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            if (token == null)
                throw new ArgumentNullException("token");

            // Note: PIN may be null when smartcard reader with pin pad is used

            privateKeys = new List<PrivateKey>();
            certificates = new List<Certificate>();

            using (Session session = token.Slot.OpenSession(SessionType.ReadOnly))
            {
                if (login == true)
                    session.Login(CKU.CKU_USER, pin);

                // Define search template for private keys
                List<ObjectAttribute> keySearchTemplate = new List<ObjectAttribute>();
                keySearchTemplate.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
                keySearchTemplate.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));

                // Define private key attributes that should be read
                List<CKA> keyAttributes = new List<CKA>();
                keyAttributes.Add(CKA.CKA_ID);
                keyAttributes.Add(CKA.CKA_LABEL);
                keyAttributes.Add(CKA.CKA_KEY_TYPE);

                // Define RSA private key attributes that should be read
                List<CKA> rsaAttributes = new List<CKA>();
                rsaAttributes.Add(CKA.CKA_MODULUS);
                rsaAttributes.Add(CKA.CKA_PUBLIC_EXPONENT);

                // Find private keys
                List<ObjectHandle> foundKeyObjects = session.FindAllObjects(keySearchTemplate);
                foreach (ObjectHandle foundKeyObject in foundKeyObjects)
                {
                    List<ObjectAttribute> keyObjectAttributes = session.GetAttributeValue(foundKeyObject, keyAttributes);

                    string ckaId = ConvertUtils.BytesToHexString(keyObjectAttributes[0].GetValueAsByteArray());
                    string ckaLabel = keyObjectAttributes[1].GetValueAsString();
                    AsymmetricKeyParameter publicKey = null;

                    if (keyObjectAttributes[2].GetValueAsUlong() == Convert.ToUInt64(CKK.CKK_RSA))
                    {
                        List<ObjectAttribute> rsaObjectAttributes = session.GetAttributeValue(foundKeyObject, rsaAttributes);

                        BigInteger modulus = new BigInteger(1, rsaObjectAttributes[0].GetValueAsByteArray());
                        BigInteger exponent = new BigInteger(1, rsaObjectAttributes[1].GetValueAsByteArray());
                        publicKey = new RsaKeyParameters(false, modulus, exponent);
                    }

                    privateKeys.Add(new PrivateKey(ckaId, ckaLabel, publicKey));
                }

                // Define search template for X.509 certificates
                List<ObjectAttribute> certSearchTemplate = new List<ObjectAttribute>();
                certSearchTemplate.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE));
                certSearchTemplate.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
                certSearchTemplate.Add(new ObjectAttribute(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509));

                // Define certificate attributes that should be read
                List<CKA> certAttributes = new List<CKA>();
                certAttributes.Add(CKA.CKA_ID);
                certAttributes.Add(CKA.CKA_LABEL);
                certAttributes.Add(CKA.CKA_VALUE);

                // Find X.509 certificates
                List<ObjectHandle> foundCertObjects = session.FindAllObjects(certSearchTemplate);
                foreach (ObjectHandle foundCertObject in foundCertObjects)
                {
                    List<ObjectAttribute> objectAttributes = session.GetAttributeValue(foundCertObject, certAttributes);

                    string ckaId = ConvertUtils.BytesToHexString(objectAttributes[0].GetValueAsByteArray());
                    string ckaLabel = objectAttributes[1].GetValueAsString();
                    byte[] ckaValue = objectAttributes[2].GetValueAsByteArray();

                    certificates.Add(new Certificate(ckaId, ckaLabel, ckaValue));
                }

                if (login == true)
                    session.Logout();
            }
        }

        #region IDisposable

        /// <summary>
        /// Disposes object
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes object
        /// </summary>
        /// <param name="disposing">Flag indicating whether managed resources should be disposed</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!this._disposed)
            {
                // Dispose managed objects
                if (disposing)
                {
                    if (_pkcs11 != null)
                    {
                        _pkcs11.Dispose();
                        _pkcs11 = null;
                    }
                }

                // Dispose unmanaged objects

                _disposed = true;
            }
        }

        /// <summary>
        /// Class destructor that disposes object if caller forgot to do so
        /// </summary>
        ~Pkcs11Explorer()
        {
            Dispose(false);
        }

        #endregion
    }
}
