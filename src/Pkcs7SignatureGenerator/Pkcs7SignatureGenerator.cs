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
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.MechanismParams;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using BCX509 = Org.BouncyCastle.X509;

namespace Pkcs7SignatureGenerator
{
    /// <summary>
    /// PKCS#7 signature creator that uses RSA private key stored on PKCS#11 compatible device.
    /// In multithreaded environment one instance of this class should be reused by all the threads.
    /// </summary>
    public class Pkcs7SignatureGenerator : IDisposable
    {
        #region Variables

        /// <summary>
        /// Flag indicating whether instance has been disposed
        /// </summary>
        private bool _disposed = false;

        /// <summary>
        /// High level PKCS#11 wrapper
        /// </summary>
        private IPkcs11Library _pkcs11Library = null;

        /// <summary>
        /// Logical reader with token used for signing
        /// </summary>
        private ISlot _slot = null;

        /// <summary>
        /// Master session where user is logged in
        /// </summary>
        private ISession _session = null;

        /// <summary>
        /// Handle of private key used for signing 
        /// </summary>
        private IObjectHandle _privateKeyHandle = null;

        /// <summary>
        /// Label (value of CKA_LABEL attribute) of the private key used for signing
        /// </summary>
        private string _ckaLabel = null;

        /// <summary>
        /// Identifier (value of CKA_ID attribute) of the private key used for signing
        /// </summary>
        private byte[] _ckaId = null;

        /// <summary>
        /// Hash algorihtm used for the signature creation
        /// </summary>
        private HashAlgorithm _hashAlgorihtm = HashAlgorithm.SHA512;

        /// <summary>
        /// Signature scheme used for the signature creation
        /// </summary>
        private SignatureScheme _signatureScheme = SignatureScheme.RSASSA_PKCS1_v1_5;

        /// <summary>
        /// Raw data of certificate related to private key used for signing
        /// </summary>
        private byte[] _signingCertificate = null;

        /// <summary>
        /// Raw data of all certificates stored in device
        /// </summary>
        private List<byte[]> _allCertificates = null;

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes a new instance of the Pkcs7Signature class
        /// </summary>
        /// <param name="libraryPath">Path to the unmanaged PCKS#11 library</param>
        /// <param name="tokenSerial">Serial number of the token (smartcard) that contains signing key. May be null if tokenLabel is specified.</param>
        /// <param name="tokenLabel">Label of of the token (smartcard) that contains signing key. May be null if tokenSerial is specified.</param>
        /// <param name="pin">PIN for the token (smartcard)</param>
        /// <param name="ckaLabel">Label (value of CKA_LABEL attribute) of the private key used for signing. May be null if ckaId is specified.</param>
        /// <param name="ckaId">Hex encoded string with identifier (value of CKA_ID attribute) of the private key used for signing. May be null if ckaLabel is specified.</param>
        /// <param name="hashAlgorihtm">Hash algorihtm used for the signature creation</param>
        /// <param name="signatureScheme">Signature scheme used for the signature creation</param>
        public Pkcs7SignatureGenerator(string libraryPath, string tokenSerial, string tokenLabel, string pin, string ckaLabel, string ckaId, HashAlgorithm hashAlgorihtm, SignatureScheme signatureScheme)
        {
            byte[] pinValue = (pin == null) ? null : ConvertUtils.Utf8StringToBytes(pin);
            byte[] ckaIdValue = (ckaId == null) ? null : ConvertUtils.HexStringToBytes(ckaId);
            InitializePkcs7RsaSignature(libraryPath, tokenSerial, tokenLabel, pinValue, ckaLabel, ckaIdValue, hashAlgorihtm, signatureScheme);
        }

        /// <summary>
        /// Initializes a new instance of the Pkcs11Signature class
        /// </summary>
        /// <param name="libraryPath">Path to the unmanaged PCKS#11 library</param>
        /// <param name="tokenSerial">Serial number of the token (smartcard) that contains signing key. May be null if tokenLabel is specified.</param>
        /// <param name="tokenLabel">Label of of the token (smartcard) that contains signing key. May be null if tokenSerial is specified.</param>
        /// <param name="pin">PIN for the token (smartcard)</param>
        /// <param name="ckaLabel">Label (value of CKA_LABEL attribute) of the private key used for signing. May be null if ckaId is specified.</param>
        /// <param name="ckaId">Identifier (value of CKA_ID attribute) of the private key used for signing. May be null if ckaLabel is specified.</param>
        /// <param name="hashAlgorihtm">Hash algorihtm used for the signature creation</param>
        /// <param name="signatureScheme">Signature scheme used for the signature creation</param>
        public Pkcs7SignatureGenerator(string libraryPath, string tokenSerial, string tokenLabel, byte[] pin, string ckaLabel, byte[] ckaId, HashAlgorithm hashAlgorihtm, SignatureScheme signatureScheme)
        {
            InitializePkcs7RsaSignature(libraryPath, tokenSerial, tokenLabel, pin, ckaLabel, ckaId, hashAlgorihtm, signatureScheme);
        }

        /// <summary>
        /// Initializes a new instance of the Pkcs11Signature class
        /// </summary>
        /// <param name="libraryPath">Path to the unmanaged PCKS#11 library</param>
        /// <param name="tokenSerial">Serial number of the token (smartcard) that contains signing key. May be null if tokenLabel is specified.</param>
        /// <param name="tokenLabel">Label of of the token (smartcard) that contains signing key. May be null if tokenSerial is specified.</param>
        /// <param name="pin">PIN for the token (smartcard)</param>
        /// <param name="ckaLabel">Label (value of CKA_LABEL attribute) of the private key used for signing. May be null if ckaId is specified.</param>
        /// <param name="ckaId">Identifier (value of CKA_ID attribute) of the private key used for signing. May be null if ckaLabel is specified.</param>
        /// <param name="hashAlgorihtm">Hash algorihtm used for the signature creation</param>
        /// <param name="signatureScheme">Signature scheme used for the signature creation</param>
        private void InitializePkcs7RsaSignature(string libraryPath, string tokenSerial, string tokenLabel, byte[] pin, string ckaLabel, byte[] ckaId, HashAlgorithm hashAlgorihtm, SignatureScheme signatureScheme)
        {
            try
            {
                if (string.IsNullOrEmpty(libraryPath))
                    throw new ArgumentNullException("libraryPath");

                Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
                _pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, libraryPath, AppType.MultiThreaded);

                _slot = FindSlot(tokenSerial, tokenLabel);
                if (_slot == null)
                    throw new TokenNotFoundException(string.Format("Token with serial \"{0}\" and label \"{1}\" was not found", tokenSerial, tokenLabel));

                _session = _slot.OpenSession(SessionType.ReadOnly);
                _session.Login(CKU.CKU_USER, pin);

                _privateKeyHandle = FindPrivateKey(ckaLabel, ckaId);

                _ckaLabel = ckaLabel;
                _ckaId = ckaId;

                if (!Enum.IsDefined(typeof(HashAlgorithm), hashAlgorihtm))
                    throw new ArgumentException("Invalid hash algorithm specified");

                _hashAlgorihtm = hashAlgorihtm;
                _signatureScheme = signatureScheme;
            }
            catch
            {
                if (_session != null)
                {
                    _session.Dispose();
                    _session = null;
                }

                if (_pkcs11Library != null)
                {
                    _pkcs11Library.Dispose();
                    _pkcs11Library = null;
                }

                throw;
            }
        }

        #endregion

        #region Certificates

        /// <summary>
        /// Gets the raw data of certificate related to private key used for signing
        /// </summary>
        /// <returns>Raw data of certificate related to private key used for signing</returns>
        public byte[] GetSigningCertificate()
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            // Don't read certificate from token if it has already been read
            if (_signingCertificate == null)
            {
                using (ISession session = _slot.OpenSession(SessionType.ReadOnly))
                {
                    List<IObjectAttribute> searchTemplate = new List<IObjectAttribute>();
                    searchTemplate.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE));
                    searchTemplate.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509));
                    if (!string.IsNullOrEmpty(_ckaLabel))
                        searchTemplate.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, _ckaLabel));
                    if (_ckaId != null)
                        searchTemplate.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, _ckaId));

                    List<IObjectHandle> foundObjects = session.FindAllObjects(searchTemplate);
                    if (foundObjects.Count < 1)
                        throw new ObjectNotFoundException(string.Format("Certificate with label \"{0}\" and id \"{1}\" was not found", _ckaLabel, (_ckaId == null) ? null : ConvertUtils.BytesToHexString(_ckaId)));
                    else if (foundObjects.Count > 1)
                        throw new ObjectNotFoundException(string.Format("More than one certificate with label \"{0}\" and id \"{1}\" was found", _ckaLabel, (_ckaId == null) ? null : ConvertUtils.BytesToHexString(_ckaId)));

                    List<CKA> attributes = new List<CKA>();
                    attributes.Add(CKA.CKA_VALUE);

                    List<IObjectAttribute> certificateAttributes = session.GetAttributeValue(foundObjects[0], attributes);
                    _signingCertificate = certificateAttributes[0].GetValueAsByteArray();
                }
            }

            return _signingCertificate;
        }

        /// <summary>
        /// Gets the raw data of all certificates stored in device
        /// </summary>
        /// <returns>Raw data of all certificates stored in device</returns>
        public List<byte[]> GetAllCertificates()
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            // Don't read certificates from token if they have already been read
            if (_allCertificates == null)
            {
                List<byte[]> certificates = new List<byte[]>();

                using (ISession session = _slot.OpenSession(SessionType.ReadOnly))
                {
                    List<IObjectAttribute> searchTemplate = new List<IObjectAttribute>();
                    searchTemplate.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE));
                    searchTemplate.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509));

                    List<CKA> attributes = new List<CKA>();
                    attributes.Add(CKA.CKA_VALUE);

                    List<IObjectHandle> foundObjects = session.FindAllObjects(searchTemplate);
                    foreach (IObjectHandle foundObject in foundObjects)
                    {
                        List<IObjectAttribute> objectAttributes = session.GetAttributeValue(foundObject, attributes);
                        certificates.Add(objectAttributes[0].GetValueAsByteArray());
                    }
                }

                _allCertificates = certificates;
            }

            return _allCertificates;
        }

        #endregion

        /// <summary>
        /// Generates PKCS#7 signature of specified data
        /// </summary>
        /// <param name="data">Data to be signed</param>
        /// <param name="detached">Flag indicating whether detached signature should be produced</param>
        /// <param name="signingCertificate">Signing certificate</param>
        /// <param name="certPath">Certification path for signing certificate</param>
        /// <returns>DER encoded PKCS#7 signature of specified data</returns>
        public byte[] GenerateSignature(byte[] data, bool detached, BCX509.X509Certificate signingCertificate, ICollection<BCX509.X509Certificate> certPath)
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            string hashOid = HashAlgorithmUtils.GetHashOid(_hashAlgorihtm);
            IDigest hashGenerator = HashAlgorithmUtils.GetHashGenerator(_hashAlgorihtm);

            // Compute hash of input data
            byte[] dataHash = ComputeDigest(hashGenerator, data);

            // Construct SignerInfo.signedAttrs
            Asn1EncodableVector signedAttributesVector = new Asn1EncodableVector();

            // Add PKCS#9 contentType signed attribute
            signedAttributesVector.Add(
                new Org.BouncyCastle.Asn1.Cms.Attribute(
                    attrType: new DerObjectIdentifier(OID.PKCS9AtContentType),
                    attrValues: new DerSet(new DerObjectIdentifier(OID.PKCS7IdData))));

            // Add PKCS#9 messageDigest signed attribute
            signedAttributesVector.Add(
                new Org.BouncyCastle.Asn1.Cms.Attribute(
                    attrType: new DerObjectIdentifier(OID.PKCS9AtMessageDigest),
                    attrValues: new DerSet(new DerOctetString(dataHash))));

            // Add PKCS#9 signingTime signed attribute
            signedAttributesVector.Add(
                new Org.BouncyCastle.Asn1.Cms.Attribute(
                    attrType: new DerObjectIdentifier(OID.PKCS9AtSigningTime),
                    attrValues: new DerSet(new Org.BouncyCastle.Asn1.Cms.Time(new DerUtcTime(DateTime.UtcNow)))));

            // Compute digest of SignerInfo.signedAttrs
            DerSet signedAttributes = new DerSet(signedAttributesVector);
            byte[] signedAttributesDigest = ComputeDigest(hashGenerator, signedAttributes.GetDerEncoded());

            // Sign digest of SignerInfo.signedAttrs with private key stored on PKCS#11 compatible device
            Asn1OctetString digestSignature = null;
            AlgorithmIdentifier digestSignatureAlgorithm = null;
            if (_signatureScheme == SignatureScheme.RSASSA_PKCS1_v1_5)
            {
                // Construct DigestInfo
                byte[] digestInfo = CreateDigestInfo(signedAttributesDigest, hashOid);

                // Sign DigestInfo with CKM_RSA_PKCS mechanism
                byte[] signature = null;

                using (ISession session = _slot.OpenSession(SessionType.ReadOnly))
                using (IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS))
                    signature = session.Sign(mechanism, _privateKeyHandle, digestInfo);

                // Construct SignerInfo.signature
                digestSignature = new DerOctetString(signature);

                // Construct SignerInfo.signatureAlgorithm
                digestSignatureAlgorithm = new AlgorithmIdentifier(
                    algorithm: new DerObjectIdentifier(OID.PKCS1RsaEncryption),
                    parameters: DerNull.Instance
                );
            }
            else if(_signatureScheme == SignatureScheme.RSASSA_PSS)
            {
                byte[] signature = null;

                using (ISession session = _slot.OpenSession(SessionType.ReadOnly))
                {
                    // Construct parameters for CKM_RSA_PKCS_PSS mechanism
                    ICkRsaPkcsPssParams pssMechanismParams = CreateCkRsaPkcsPssParams(session, _hashAlgorihtm);

                    // Sign digest with CKM_RSA_PKCS_PSS mechanism
                    using (IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_PSS, pssMechanismParams))
                        signature = session.Sign(mechanism, _privateKeyHandle, signedAttributesDigest);
                }

                // Construct SignerInfo.signature
                digestSignature = new DerOctetString(signature);

                // Construct SignerInfo.signatureAlgorithm
                digestSignatureAlgorithm = new AlgorithmIdentifier(
                    algorithm: new DerObjectIdentifier(OID.PKCS1RsassaPss),
                    parameters: new Org.BouncyCastle.Asn1.Pkcs.RsassaPssParameters(
                        hashAlgorithm: new AlgorithmIdentifier(
                            algorithm: new DerObjectIdentifier(hashOid),
                            parameters: DerNull.Instance
                        ),
                        maskGenAlgorithm: new AlgorithmIdentifier(
                            algorithm: new DerObjectIdentifier(OID.PKCS1Mgf1),
                            parameters: new AlgorithmIdentifier(
                                algorithm: new DerObjectIdentifier(hashOid),
                                parameters: DerNull.Instance
                            )
                        ),
                        saltLength: new DerInteger(hashGenerator.GetDigestSize()),
                        trailerField: new DerInteger(1)
                    )
                );
            }
            else
            {
                throw new NotSupportedException("Unsupported signature scheme");
            }

            // Construct SignerInfo
            SignerInfo signerInfo = new SignerInfo(
                sid: new SignerIdentifier(new IssuerAndSerialNumber(signingCertificate.IssuerDN, signingCertificate.SerialNumber)),
                digAlgorithm: new AlgorithmIdentifier(
                    algorithm: new DerObjectIdentifier(hashOid),
                    parameters: DerNull.Instance
                ),
                authenticatedAttributes: signedAttributes,
                digEncryptionAlgorithm: digestSignatureAlgorithm,
                encryptedDigest: digestSignature,
                unauthenticatedAttributes: null
            );

            // Construct SignedData.digestAlgorithms
            Asn1EncodableVector digestAlgorithmsVector = new Asn1EncodableVector();
            digestAlgorithmsVector.Add(
                new AlgorithmIdentifier(
                    algorithm: new DerObjectIdentifier(hashOid),
                    parameters: DerNull.Instance));

            // Construct SignedData.encapContentInfo
            ContentInfo encapContentInfo = new ContentInfo(
                contentType: new DerObjectIdentifier(OID.PKCS7IdData),
                content: (detached) ? null : new DerOctetString(data));

            // Construct SignedData.certificates
            Asn1EncodableVector certificatesVector = new Asn1EncodableVector();
            foreach (BCX509.X509Certificate cert in certPath)
                certificatesVector.Add(X509CertificateStructure.GetInstance(Asn1Object.FromByteArray(cert.GetEncoded())));

            // Construct SignedData.signerInfos
            Asn1EncodableVector signerInfosVector = new Asn1EncodableVector();
            signerInfosVector.Add(signerInfo.ToAsn1Object());

            // Construct SignedData
            SignedData signedData = new SignedData(
                digestAlgorithms: new DerSet(digestAlgorithmsVector),
                contentInfo: encapContentInfo,
                certificates: new BerSet(certificatesVector),
                crls: null,
                signerInfos: new DerSet(signerInfosVector));

            // Construct top level ContentInfo
            ContentInfo contentInfo = new ContentInfo(
                contentType: new DerObjectIdentifier(OID.PKCS7IdSignedData),
                content: signedData);

            return contentInfo.GetDerEncoded();
        }

        #region Private methods

        /// <summary>
        /// Finds slot containing the token that matches specified criteria
        /// </summary>
        /// <param name="tokenSerial">Serial number of token that should be found</param>
        /// <param name="tokenLabel">Label of token that should be found</param>
        /// <returns>Slot containing the token that matches specified criteria</returns>
        private ISlot FindSlot(string tokenSerial, string tokenLabel)
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            if (string.IsNullOrEmpty(tokenSerial) && string.IsNullOrEmpty(tokenLabel))
                throw new ArgumentException("Token serial and/or label has to be specified");

            List<ISlot> slots = _pkcs11Library.GetSlotList(SlotsType.WithTokenPresent);
            foreach (ISlot slot in slots)
            {
                ITokenInfo tokenInfo = null;

                try
                {
                    tokenInfo = slot.GetTokenInfo();
                }
                catch (Pkcs11Exception ex)
                {
                    if (ex.RV != CKR.CKR_TOKEN_NOT_RECOGNIZED && ex.RV != CKR.CKR_TOKEN_NOT_PRESENT)
                        throw;
                }

                if (tokenInfo == null)
                    continue;

                if (!string.IsNullOrEmpty(tokenSerial))
                    if (0 != String.Compare(tokenSerial, tokenInfo.SerialNumber, StringComparison.InvariantCultureIgnoreCase))
                        continue;

                if (!string.IsNullOrEmpty(tokenLabel))
                    if (0 != String.Compare(tokenLabel, tokenInfo.Label, StringComparison.InvariantCultureIgnoreCase))
                        continue;

                return slot;
            }

            return null;
        }

        /// <summary>
        /// Finds private key that matches specified criteria
        /// </summary>
        /// <param name="ckaLabel">Label (value of CKA_LABEL attribute) of the private key</param>
        /// <param name="ckaId">Identifier (value of CKA_ID attribute) of the private key</param>
        /// <returns>Handle of private key that matches specified criteria</returns>
        private IObjectHandle FindPrivateKey(string ckaLabel, byte[] ckaId)
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            if (string.IsNullOrEmpty(ckaLabel) && ckaId == null)
                throw new ArgumentException("Private key label and/or id has to be specified");

            using (ISession session = _slot.OpenSession(SessionType.ReadOnly))
            {
                List<IObjectAttribute> searchTemplate = new List<IObjectAttribute>();
                searchTemplate.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
                searchTemplate.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA));
                if (!string.IsNullOrEmpty(ckaLabel))
                    searchTemplate.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, ckaLabel));
                if (ckaId != null)
                    searchTemplate.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckaId));

                List<IObjectHandle> foundObjects = session.FindAllObjects(searchTemplate);
                if (foundObjects.Count < 1)
                    throw new ObjectNotFoundException(string.Format("Private key with label \"{0}\" and id \"{1}\" was not found", ckaLabel, (ckaId == null) ? null : ConvertUtils.BytesToHexString(ckaId)));
                else if (foundObjects.Count > 1)
                    throw new ObjectNotFoundException(string.Format("More than one private key with label \"{0}\" and id \"{1}\" was found", ckaLabel, (ckaId == null) ? null : ConvertUtils.BytesToHexString(ckaId)));

                return foundObjects[0];
            }
        }

        /// <summary>
        /// Creates parameters for CKM_RSA_PKCS_PSS mechanism
        /// </summary>
        /// <param name="session">PKCS#11 session in which signing will be performed</param>
        /// <param name="hashAlgorithm">Hash algorithm</param>
        /// <returns>Parameters for CKM_RSA_PKCS_PSS mechanism</returns>
        private static ICkRsaPkcsPssParams CreateCkRsaPkcsPssParams(ISession session, HashAlgorithm hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
                case HashAlgorithm.SHA1:
                    return session.Factories.MechanismParamsFactory.CreateCkRsaPkcsPssParams(
                        hashAlg: (ulong)CKM.CKM_SHA_1,
                        mgf: (ulong)CKG.CKG_MGF1_SHA1,
                        len: (ulong)HashAlgorithmUtils.GetHashGenerator(hashAlgorithm).GetDigestSize()
                    );
                case HashAlgorithm.SHA256:
                    return session.Factories.MechanismParamsFactory.CreateCkRsaPkcsPssParams(
                        hashAlg: (ulong)CKM.CKM_SHA256,
                        mgf: (ulong)CKG.CKG_MGF1_SHA256,
                        len: (ulong)HashAlgorithmUtils.GetHashGenerator(hashAlgorithm).GetDigestSize()
                    );
                case HashAlgorithm.SHA384:
                    return session.Factories.MechanismParamsFactory.CreateCkRsaPkcsPssParams(
                        hashAlg: (ulong)CKM.CKM_SHA384,
                        mgf: (ulong)CKG.CKG_MGF1_SHA384,
                        len: (ulong)HashAlgorithmUtils.GetHashGenerator(hashAlgorithm).GetDigestSize()
                    );
                case HashAlgorithm.SHA512:
                    return session.Factories.MechanismParamsFactory.CreateCkRsaPkcsPssParams(
                        hashAlg: (ulong)CKM.CKM_SHA512,
                        mgf: (ulong)CKG.CKG_MGF1_SHA512,
                        len: (ulong)HashAlgorithmUtils.GetHashGenerator(hashAlgorithm).GetDigestSize()
                    );
                default:
                    throw new NotSupportedException("Unsupported hash algorithm");
            }
        }

        /// <summary>
        /// Creates PKCS#1 DigestInfo
        /// </summary>
        /// <param name="hash">Hash value</param>
        /// <param name="hashOid">Hash algorithm OID</param>
        /// <returns>DER encoded PKCS#1 DigestInfo</returns>
        private static byte[] CreateDigestInfo(byte[] hash, string hashOid)
        {
            DigestInfo digestInfo = new DigestInfo(
                algID: new AlgorithmIdentifier(
                    algorithm: new DerObjectIdentifier(hashOid),
                    parameters: DerNull.Instance
                ),
                digest: hash
            );

            return digestInfo.GetDerEncoded();
        }

        /// <summary>
        /// Computes hash of the data
        /// </summary>
        /// <param name="digest">Hash algorithm implementation</param>
        /// <param name="data">Data that should be processed</param>
        /// <returns>Hash of data</returns>
        private static byte[] ComputeDigest(IDigest digest, byte[] data)
        {
            if (digest == null)
                throw new ArgumentNullException("digest");

            if (data == null)
                throw new ArgumentNullException("data");

            byte[] hash = new byte[digest.GetDigestSize()];

            digest.Reset();
            digest.BlockUpdate(data, 0, data.Length);
            digest.DoFinal(hash, 0);

            return hash;
        }

        #endregion

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
                    _allCertificates = null;
                    _signingCertificate = null;
                    _hashAlgorihtm = HashAlgorithm.SHA512;
                    _ckaId = null;
                    _ckaLabel = null;
                    _privateKeyHandle = null;

                    if (_session != null)
                    {
                        try
                        {
                            _session.Logout();
                        }
                        catch
                        {
                            // Any exceptions can be safely ignored here
                        }

                        _session.Dispose();
                        _session = null;
                    }
                    
                    _slot = null;
                    
                    if (_pkcs11Library != null)
                    {
                        _pkcs11Library.Dispose();
                        _pkcs11Library = null;
                    }
                }
                
                // Dispose unmanaged objects

                _disposed = true;
            }
        }
        
        /// <summary>
        /// Class destructor that disposes object if caller forgot to do so
        /// </summary>
        ~Pkcs7SignatureGenerator()
        {
            Dispose(false);
        }

        #endregion
    }
}
