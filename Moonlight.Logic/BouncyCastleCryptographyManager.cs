namespace Moonlight.Xbox.Logic
{
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Generators;
    using Org.BouncyCastle.Crypto.Operators;
    using Org.BouncyCastle.Crypto.Prng;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Pkcs;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.X509;
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Runtime.InteropServices.WindowsRuntime;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Windows.Security.Cryptography;
    using Windows.Security.Cryptography.Certificates;
    using BouncyCastleX509Certificate = Org.BouncyCastle.X509.X509Certificate;

    public class BouncyCastleCryptographyManager
    {
        private const string CertificateFriendlyName = "Moonlight Xbox";

        /// <summary>
        /// A password appears to be required so use a dumb one.
        /// </summary>
        private const string CertificatePassword = "password";

        private readonly SecureRandom secureRandom;

        public BouncyCastleCryptographyManager(IRandomGenerator randomGenerator)
        {
            this.secureRandom = new SecureRandom(randomGenerator);
        }

        public async Task<X509Certificate2> GetHttpsCertificateAsync()
        {
            // This function queries the app certificate store. For now, there should always
            // be 0-1 items.
            IReadOnlyList<Certificate> certificates = await CertificateStores.FindAllAsync();
            if (certificates.Count == 0)
            {
                return null;
            }

            return new X509Certificate2(
                certificates[0].GetCertificateBlob().ToArray(),
                CertificatePassword);
        }

        public async Task<X509Certificate2> CreateHttpsCertificateAsync()
        {
            // Create asymmetric key pair using 2048 bit RSA.
            RsaKeyPairGenerator keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(new KeyGenerationParameters(this.secureRandom, 2048));
            AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();

            // Certificate issuer and name
            X509Name name = new X509Name("CN=NVIDIA GameStream Client");

            // Certificate serial number
            byte[] serialBytes = this.GenerateRandomBytes(8);
            BigInteger serial = new BigInteger(serialBytes).Abs();

            // Expires in 20 years
            DateTime now = DateTime.UtcNow;
            DateTime expiration = now.AddYears(20);

            // Generate the Bouncy Castle certificate.
            X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
            generator.SetSubjectDN(name);
            generator.SetIssuerDN(name);
            generator.SetSerialNumber(serial);
            generator.SetNotBefore(now);
            generator.SetNotAfter(expiration);
            generator.SetPublicKey(keyPair.Public);

            BouncyCastleX509Certificate certificate =
                generator.Generate(
                    new Asn1SignatureFactory("SHA1WithRSA", keyPair.Private));

            // Generate PKCS12 certificate bytes.
            Pkcs12Store store = new Pkcs12Store();
            X509CertificateEntry certificateEntry = new X509CertificateEntry(certificate);
            store.SetCertificateEntry(CertificateFriendlyName, certificateEntry);
            store.SetKeyEntry(
                CertificateFriendlyName,
                new AsymmetricKeyEntry(keyPair.Private),
                new X509CertificateEntry[] { certificateEntry });
            byte[] pfxDataBytes;
            using (MemoryStream memoryStream = new MemoryStream(512))
            {
                store.Save(memoryStream, CertificatePassword.ToCharArray(), this.secureRandom);
                pfxDataBytes = memoryStream.ToArray();
            }

            await CertificateEnrollmentManager.ImportPfxDataAsync(
                CryptographicBuffer.EncodeToBase64String(pfxDataBytes.AsBuffer()),
                CertificatePassword,
                ExportOption.NotExportable,
                KeyProtectionLevel.NoConsent,
                InstallOptions.DeleteExpired,
                CertificateFriendlyName);

            return new X509Certificate2(
                pfxDataBytes,
                CertificatePassword);
        }

        public byte[] GenerateRandomBytes(int length)
        {
            byte[] randomBytes = new byte[length];
            this.secureRandom.NextBytes(randomBytes);

            return randomBytes;
        }
    }
}
