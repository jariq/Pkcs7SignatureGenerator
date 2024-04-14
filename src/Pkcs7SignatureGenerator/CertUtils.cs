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
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.X509.Store;
using BCCollections = Org.BouncyCastle.Utilities.Collections;
using BCX509 = Org.BouncyCastle.X509;

namespace Pkcs7SignatureGenerator
{
    /// <summary>
    /// Utility class that helps with certificate processing
    /// </summary>
    public static class CertUtils
    {
        /// <summary>
        /// BouncyCastle certificate parser
        /// </summary>
        private static BCX509.X509CertificateParser _x509CertificateParser = new BCX509.X509CertificateParser();

        /// <summary>
        /// Converts raw certificate data to the instance of .NET X509Certificate2 class
        /// </summary>
        /// <param name="data">Raw certificate data</param>
        /// <returns>Instance of .NET X509Certificate2 class</returns>
        public static X509Certificate2 ToDotNetObject(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            return new X509Certificate2(data);
        }

        /// <summary>
        /// Converts the instance of BouncyCastle X509Certificate class to the instance of .NET X509Certificate2 class
        /// </summary>
        /// <param name="cert">Instance of BouncyCastle X509Certificate class</param>
        /// <returns>Instance of .NET X509Certificate2 class</returns>
        public static X509Certificate2 ToDotNetObject(BCX509.X509Certificate cert)
        {
            if (cert == null)
                throw new ArgumentNullException("cert");

            return new X509Certificate2(ToDerEncodedByteArray(cert));
        }

        /// <summary>
        /// Converts raw certificate data to the instance of BouncyCastle X509Certificate class
        /// </summary>
        /// <param name="data">Raw certificate data</param>
        /// <returns>Instance of BouncyCastle X509Certificate class</returns>
        public static BCX509.X509Certificate ToBouncyCastleObject(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            BCX509.X509Certificate bcCert = _x509CertificateParser.ReadCertificate(data);
            if (bcCert == null)
                throw new Exception("Provided data do not represent X.509 certificate");

            return bcCert;
        }

        /// <summary>
        /// Converts the instance of .NET X509Certificate2 class to the instance of BouncyCastle X509Certificate class
        /// </summary>
        /// <param name="cert">Instance of .NET X509Certificate2 class</param>
        /// <returns>Instance of BouncyCastle X509Certificate class</returns>
        public static BCX509.X509Certificate ToBouncyCastleObject(X509Certificate2 cert)
        {
            if (cert == null)
                throw new ArgumentNullException("cert");

            BCX509.X509Certificate bcCert = _x509CertificateParser.ReadCertificate(cert.RawData);
            if (bcCert == null)
                throw new Exception("Provided data do not represent X.509 certificate");

            return bcCert;
        }

        /// <summary>
        /// Converts the instance of BouncyCastle X509Certificate class to the DER encoded byte array
        /// </summary>
        /// <param name="cert">Instance of BouncyCastle X509Certificate class</param>
        /// <returns>DER encoded byte array</returns>
        public static byte[] ToDerEncodedByteArray(BCX509.X509Certificate cert)
        {
            if (cert == null)
                throw new ArgumentNullException("cert");

            return cert.GetEncoded();
        }

        /// <summary>
        /// Converts the instance of .NET X509Certificate2 class to the DER encoded byte array
        /// </summary>
        /// <param name="cert">Instance of .NET X509Certificate2 class</param>
        /// <returns>DER encoded byte array</returns>
        public static byte[] ToDerEncodedByteArray(X509Certificate2 cert)
        {
            if (cert == null)
                throw new ArgumentNullException("cert");

            return cert.RawData;
        }

        /// <summary>
        /// Checks whether certificate is self-signed
        /// </summary>
        /// <param name="certificate">Certificate to be checked</param>
        /// <returns>True if certificate is self-signed; false otherwise</returns>
        public static bool IsSelfSigned(BCX509.X509Certificate certificate)
        {
            if (certificate == null)
                throw new ArgumentNullException("certificate");

            try
            {
                certificate.Verify(certificate.GetPublicKey());
                return true;
            }
            catch (Org.BouncyCastle.Security.InvalidKeyException)
            {
                return false;
            }
        }

        /// <summary>
        /// Builds certification path for provided signing certificate
        /// </summary>
        /// <param name="signingCertificate">Signing certificate</param>
        /// <param name="otherCertificates">Other certificates that should be used in path building process. Self-signed certificates from this list are used as trust anchors.</param>
        /// <param name="includeRoot">Flag indicating whether root certificate should be included int the certification path.</param>
        /// <returns>Certification path for provided signing certificate</returns>
        public static ICollection<BCX509.X509Certificate> BuildCertPath(byte[] signingCertificate, List<byte[]> otherCertificates, bool includeRoot)
        {
            if (signingCertificate == null)
                throw new ArgumentNullException("signingCertificate");

            List<BCX509.X509Certificate> result = new List<BCX509.X509Certificate>();

            BCX509.X509Certificate signingCert = ToBouncyCastleObject(signingCertificate);
            HashSet<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
            List<BCX509.X509Certificate> otherCerts = new List<BCX509.X509Certificate>();

            if (IsSelfSigned(signingCert))
            {
                if (includeRoot)
                    result.Add(signingCert);
            }
            else
            {
                otherCerts.Add(signingCert);

                if (otherCertificates != null)
                {
                    foreach (byte[] otherCertificate in otherCertificates)
                    {
                        BCX509.X509Certificate otherCert = ToBouncyCastleObject(otherCertificate);
                        otherCerts.Add(ToBouncyCastleObject(otherCertificate));
                        if (IsSelfSigned(otherCert))
                            trustAnchors.Add(new TrustAnchor(otherCert, null));
                    }
                }

                if (trustAnchors.Count < 1)
                    throw new PkixCertPathBuilderException("Provided certificates do not contain self-signed root certificate");

                X509CertStoreSelector targetConstraints = new X509CertStoreSelector();
                targetConstraints.Certificate = signingCert;

                PkixBuilderParameters certPathBuilderParameters = new PkixBuilderParameters(trustAnchors, targetConstraints);
                certPathBuilderParameters.AddStoreCert(BCCollections.CollectionUtilities.CreateStore(otherCerts));
                certPathBuilderParameters.IsRevocationEnabled = false;

                PkixCertPathBuilder certPathBuilder = new PkixCertPathBuilder();
                PkixCertPathBuilderResult certPathBuilderResult = certPathBuilder.Build(certPathBuilderParameters);

                foreach (BCX509.X509Certificate certPathCert in certPathBuilderResult.CertPath.Certificates)
                    result.Add(certPathCert);

                if (includeRoot)
                    result.Add(certPathBuilderResult.TrustAnchor.TrustedCert);
            }

            return result;
        }
    }
}
