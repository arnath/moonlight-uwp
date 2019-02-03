namespace Moonlight.Xbox.Logic.Cryptography
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Runtime.InteropServices.WindowsRuntime;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading.Tasks;
    using Windows.Security.Cryptography;
    using Windows.Security.Cryptography.Certificates;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Generators;
    using Org.BouncyCastle.Crypto.Operators;
    using Org.BouncyCastle.Crypto.Prng;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.OpenSsl;
    using Org.BouncyCastle.Pkcs;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.X509;
    using BouncyCastleX509Certificate = Org.BouncyCastle.X509.X509Certificate;

    public class BouncyCastleCryptographyManager
    {
        /// <summary>
        /// The certificate is usually around 2400 bytes. Ensure the memory stream
        /// buffer is large enough to fit the whole thing without expanding.
        /// </summary>
        private const int CertificateBufferSize = 2560;

        private const string CertificateFriendlyName = "Moonlight Xbox";

        private const string HexAlphabet = "0123456789abcdef";

        private static readonly int[] HexValues =
            new int[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

        /// <summary>
        /// A password appears to be required so use a dumb one.
        /// </summary>
        private const string CertificatePassword = "password";

        private readonly SecureRandom secureRandom;

        private readonly IDigest hashAlgorithm;

        private readonly ISigner signer;

        private readonly X509CertificateParser certificateParser = new X509CertificateParser();

        public BouncyCastleCryptographyManager(IDigest hashAlgorithm, ISigner signer)
        {
            if (hashAlgorithm == null)
            {
                throw new ArgumentNullException(nameof(hashAlgorithm));
            }

            if (signer == null)
            {
                throw new ArgumentNullException(nameof(signer));
            }

            this.secureRandom = new SecureRandom(new CryptoApiRandomGenerator());
            this.hashAlgorithm = hashAlgorithm;
            this.HashDigestSize = this.hashAlgorithm.GetDigestSize();
            this.signer = signer;
        }

        public int HashDigestSize { get; }

        public static string BytesToHex(byte[] value)
        {
            StringBuilder result = new StringBuilder(value.Length * 2);
            foreach (byte b in value)
            {
                result.Append(HexAlphabet[b >> 4]);
                result.Append(HexAlphabet[b & 0x0F]);
            }

            return result.ToString();
        }

        public static byte[] HexToBytes(string value)
        {
            value = value.ToUpperInvariant();
            int numChars = value.Length;
            byte[] byteValue = new byte[numChars / 2];
            for (int i = 0; i < numChars; i += 2)
            {
                byteValue[i / 2] = (byte)(HexValues[value[i] - '0'] << 4 | HexValues[value[i + 1] - '0']);
            }

            return byteValue;
        }

        public static byte[] ConcatenateByteArrays(params byte[][] byteArrays)
        {
            if (byteArrays.Length < 2)
            {
                throw new ArgumentException("Cannot concatenate less than two arrays.", nameof(byteArrays));
            }

            int totalLength = 0;
            for (int i = 0; i < byteArrays.Length; i++)
            {
                totalLength += byteArrays[i].Length;
            }

            byte[] result = new byte[totalLength];
            int position = 0;
            for (int i = 0; i < byteArrays.Length; i++)
            {
                Array.Copy(byteArrays[i], 0, result, position, byteArrays[i].Length);
                position += byteArrays[i].Length;
            }

            return result;
        }

        public static byte[] SaltData(byte[] salt, string data)
        {
            byte[] saltedData = new byte[salt.Length + data.Length];
            Array.Copy(salt, 0, saltedData, 0, salt.Length);
            Encoding.UTF8.GetBytes(data, 0, data.Length, saltedData, salt.Length);

            return saltedData;
        }

        public static byte[] GetPemEncodedCertificate(X509Certificate2 certificate)
        {
            BouncyCastleX509Certificate bouncyCastleCertificate = DotNetUtilities.FromX509Certificate(certificate);
            using (StringWriter certWriter = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(certWriter);
                pemWriter.WriteObject(certificate);

                // Line endings must be UNIX style for GFE to accept the certificate.
                certWriter.GetStringBuilder().Replace(Environment.NewLine, "\n");

                return Encoding.UTF8.GetBytes(certWriter.ToString());
            }
        }

        public static byte[] GetCertificateSignature(X509Certificate2 certificate)
        {
            return DotNetUtilities.FromX509Certificate(certificate).GetSignature();
        }

        public BouncyCastleX509Certificate ParseCertificate(string certificateString)
        {
            byte[] certificateBytes = BouncyCastleCryptographyManager.HexToBytes(certificateString);
            return this.certificateParser.ReadCertificate(certificateBytes);
        }

        public async Task<X509Certificate2> GetOrCreateHttpsCertificateAsync()
        {
            return await this.GetHttpsCertificateAsync() ?? await this.CreateHttpsCertificateAsync();
        }

        // TODO: Consider making this private.
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

        // TODO: Consider making this private.
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
            using (MemoryStream memoryStream = new MemoryStream(CertificateBufferSize))
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

        public byte[] HashData(byte[] data)
        {
            byte[] hashedData = new byte[this.HashDigestSize];
            this.hashAlgorithm.BlockUpdate(data, 0, data.Length);
            this.hashAlgorithm.DoFinal(hashedData, 0);

            return hashedData;
        }

        public byte[] SignData(byte[] data, AsymmetricAlgorithm privateKey)
        {
            AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetKeyPair(privateKey);
            this.signer.Init(true, keyPair.Private);
            this.signer.BlockUpdate(data, 0, data.Length);

            return signer.GenerateSignature();
        }

        public bool VerifySignature(byte[] data, byte[] signature, BouncyCastleX509Certificate certificate)
        {
            this.signer.Init(false, certificate.GetPublicKey());
            this.signer.BlockUpdate(data, 0, data.Length);

            return this.signer.VerifySignature(signature);
        }

        public byte[] GenerateRandomBytes(int length)
        {
            byte[] randomBytes = new byte[length];
            this.secureRandom.NextBytes(randomBytes);

            return randomBytes;
        }
    }
}
