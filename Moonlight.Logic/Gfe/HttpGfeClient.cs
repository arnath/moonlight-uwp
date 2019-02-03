namespace Moonlight.Xbox.Logic.Gfe
{
    using System;
    using System.Collections.Concurrent;
    using System.Linq;
    using System.Net.Http;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using System.Xml.Serialization;
    using Moonlight.Xbox.Logic.Cryptography;
    using BouncyCastleX509Certificate = Org.BouncyCastle.X509.X509Certificate;

    public class HttpGfeClient
    {
        /// <summary>
        /// Use the same unique ID for all Moonlight clients so we can quit games
        /// started by other Moonlight clients.
        /// </summary>
        private const string UniqueId = "0123456789ABCDEF";

        private static readonly ConcurrentDictionary<Type, XmlSerializer> XmlSerializers =
            new ConcurrentDictionary<Type, XmlSerializer>();

        private readonly HttpClient httpClient;

        private readonly HttpClientHandler httpClientHandler;

        private readonly Uri baseUrlHttp;

        private readonly Uri baseUrlHttps;

        private readonly BouncyCastleCryptographyManager cryptographyManager;

        public HttpGfeClient()
        {
            this.httpClientHandler = new HttpClientHandler();
            this.httpClientHandler.ServerCertificateCustomValidationCallback = (a, b, c, d) => true;
        }

        public Task<ServerInfoResponse> GetServerInfoAsync()
        {
            return this.DoGetRequestAsync<ServerInfoResponse>(
                this.baseUrlHttps,
                "/serverinfo");
        }

        public async Task<Result> PairAsync()
        {
            // Generate a random 4-digit PIN.
            string pin = new Random().Next(10000).ToString("D4");

            // Generate salt value.
            byte[] salt = this.cryptographyManager.GenerateRandomBytes(16);

            // Get or create HTTPs certificate and add it to the HTTP client.
            X509Certificate2 certificate = await this.cryptographyManager.GetOrCreateHttpsCertificateAsync();
            this.httpClientHandler.ClientCertificates.Add(certificate);

            // Get PEM encoded certificate;
            byte[] pemCertificate = BouncyCastleCryptographyManager.GetPemEncodedCertificate(certificate);

            // Get the server certificate.
            string queryString =
                string.Format(
                    "deviceName=roth&updateState=1&phrase=getservercert&salt={0}&clientcert={1}",
                    BouncyCastleCryptographyManager.BytesToHex(salt),
                    BouncyCastleCryptographyManager.BytesToHex(pemCertificate));
            PairResponse pairResponse = await this.DoGetRequestAsync<PairResponse>(this.baseUrlHttp, "/pair", queryString);
            if (pairResponse == null || pairResponse.Paired != 1)
            {
                // TODO: Change this error code.
                return new Result(0, "Pairing failed with unknown error.");
            }

            if (string.IsNullOrWhiteSpace(pairResponse.PlainCert))
            {
                // Attempting to pair while another device is pairing will cause GFE
                // to give an empty cert in the response.
                // TODO: Change this error code.
                return new Result(0, "Pairing already in progress");
            }

            BouncyCastleX509Certificate serverCertificate = this.cryptographyManager.ParseCertificate(pairResponse.PlainCert);

            // Salt and hash pin and use it to create an AES cipher.
            byte[] saltedAndHashedPin = this.cryptographyManager.HashData(BouncyCastleCryptographyManager.SaltData(salt, pin));
            AesCipher cipher = new AesCipher(saltedAndHashedPin);

            // Generate a random challenge and encrypt it using AES.
            byte[] clientChallenge = this.cryptographyManager.GenerateRandomBytes(16);
            byte[] encryptedClientChallenge = cipher.Encrypt(clientChallenge);

            // Send the challenge to the server.
            queryString = $"devicename=roth&updateState=1&clientchallenge={BouncyCastleCryptographyManager.BytesToHex(encryptedClientChallenge)}";
            pairResponse = await this.DoGetRequestAsync<PairResponse>(this.baseUrlHttp, "/pair", queryString);
            if (pairResponse == null || pairResponse.Paired != 1 || string.IsNullOrWhiteSpace(pairResponse.ChallengeResponse))
            {
                // TODO: Change this error code.
                // TODO: Unpair here.
                return new Result(0, "Pairing failed with unknown error.");
            }

            // Decrypt and parse the server's challenge response and subsequent challenge.
            byte[] decryptedServerChallengeResponse = cipher.Decrypt(BouncyCastleCryptographyManager.HexToBytes(pairResponse.ChallengeResponse));
            byte[] serverResponse = new byte[this.cryptographyManager.HashDigestSize];
            byte[] serverChallenge = new byte[16];
            Array.Copy(decryptedServerChallengeResponse, serverResponse, this.cryptographyManager.HashDigestSize);
            Array.Copy(decryptedServerChallengeResponse, this.cryptographyManager.HashDigestSize, serverChallenge, 0, 16);

            // Using another 16 byte secret, compute a challenge response hash using the secret, 
            // our certificate signature, and the challenge.
            byte[] clientSecret = this.cryptographyManager.GenerateRandomBytes(16);
            byte[] challengeResponseHash =
                this.cryptographyManager.HashData(
                    BouncyCastleCryptographyManager.ConcatenateByteArrays(
                        serverChallenge, 
                        BouncyCastleCryptographyManager.GetCertificateSignature(certificate), 
                        clientSecret));
            byte[] encryptedChallengeResponse = cipher.Encrypt(challengeResponseHash);

            // Send the challenge response to the server.
            queryString = $"devicename=roth&updateState=1&serverchallengeresp={BouncyCastleCryptographyManager.BytesToHex(encryptedChallengeResponse)}";
            pairResponse = await this.DoGetRequestAsync<PairResponse>(this.baseUrlHttp, "/pair", queryString);
            if (pairResponse == null || pairResponse.Paired != 1 || string.IsNullOrWhiteSpace(pairResponse.PairingSecret))
            {
                // TODO: Change this error code.
                // TODO: Unpair here.
                return new Result(0, "Pairing failed with unknown error.");
            }

            // Get the server's signed secret.
            byte[] serverSecretResponse = BouncyCastleCryptographyManager.HexToBytes(pairResponse.PairingSecret);
            byte[] serverSecret = new byte[16];
            byte[] serverSignature = new byte[256];
            Array.Copy(serverSecretResponse, serverSecret, serverSecret.Length);
            Array.Copy(serverSecretResponse, serverSecret.Length, serverSignature, 0, serverSignature.Length);

            // Ensure the authenticity of the data.
            if (!this.cryptographyManager.VerifySignature(serverSecret, serverSignature, serverCertificate))
            {
                // TODO: Change this error code.
                // TODO: Unpair here.
                return new Result(0, "Pairing failed with invalid signature.");
            }

            // Ensure the server challenge matched what we expected (the PIN was correct).
            byte[] serverChallengeResponseHash =
                this.cryptographyManager.HashData(
                    BouncyCastleCryptographyManager.ConcatenateByteArrays(
                        clientChallenge,
                        serverCertificate.GetSignature(),
                        serverSecret));
            if (!serverChallengeResponseHash.SequenceEqual(serverResponse))
            {
                // TODO: Change this error code.
                // TODO: Unpair here.
                return new Result(0, "Pairing failed with incorrect PIN.");
            }

            // Create our signed secret.
            byte[] signedSecret = this.cryptographyManager.SignData(clientSecret, certificate.PrivateKey);
            byte[] clientPairingSecret = 
                BouncyCastleCryptographyManager.ConcatenateByteArrays(
                    clientSecret,
                    signedSecret);

            // Send it to the server.
            queryString = $"devicename=roth&updateState=1&clientpairingsecret={BouncyCastleCryptographyManager.BytesToHex(clientPairingSecret)}";
            pairResponse = await this.DoGetRequestAsync<PairResponse>(this.baseUrlHttp, "/pair", queryString);
            if (pairResponse == null || pairResponse.Paired != 1)
            {
                // TODO: Change this error code.
                // TODO: Unpair here.
                return new Result(0, "Pairing failed with unknown error.");
            }

            // Do the initial challenge (seems neccessary for us to show as paired).
            pairResponse = 
                await this.DoGetRequestAsync<PairResponse>(
                    this.baseUrlHttps, 
                    "/pair", 
                    "devicename=roth&updateState=1&phrase=pairchallenge");
            if (pairResponse == null || pairResponse.Paired != 1)
            {
                // TODO: Change this error code.
                // TODO: Unpair here.
                return new Result(0, "Pairing failed with unknown error.");
            }

            return new Result();
        }

        private Task<TResponse> DoGetRequestAsync<TResponse>(Uri baseUri, string resourcePath) where TResponse : class
        {
            return this.DoGetRequestAsync<TResponse>(baseUri, resourcePath, null);
        }

        private async Task<TResponse> DoGetRequestAsync<TResponse>(
            Uri baseUrl, 
            string resourcePath, 
            string queryString) where TResponse : class
        {
            try
            {
                string requestUrl = null;
                if (string.IsNullOrWhiteSpace(queryString))
                {
                    requestUrl = $"{baseUrl}/{resourcePath}?uniqueid={UniqueId}&uuid={Guid.NewGuid():N}";
                }
                else
                {
                    requestUrl = $"{baseUrl}{resourcePath}?uniqueid={UniqueId}&uuid={Guid.NewGuid():N}&{queryString}";
                }

                using (HttpResponseMessage response = await this.httpClient.GetAsync(requestUrl))
                {
                    if (!response.IsSuccessStatusCode)
                    {
                        // Log?
                        return null;
                    }

                    XmlSerializer serializer = XmlSerializers.GetOrAdd(
                        typeof(TResponse),
                        (type) => new XmlSerializer(type));
                    return serializer.Deserialize(await response.Content.ReadAsStreamAsync()) as TResponse;
                }
            }
            catch (Exception e)
            {
                // Log?
                return null;
            }
        }
    }
}
