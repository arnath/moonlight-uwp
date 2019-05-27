namespace Moonlight.Xbox.Logic.Gfe
{
    using System;
    using System.Collections.Concurrent;
    using System.IO;
    using System.Linq;
    using System.Net.Http;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using System.Xml.Serialization;
    using Moonlight.Xbox.Logic.Cryptography;
    using BouncyCastleX509Certificate = Org.BouncyCastle.X509.X509Certificate;

    public class HttpGfeClient : IDisposable
    {
        /// <summary>
        /// Use the same unique ID for all Moonlight clients so we can quit games
        /// started by other Moonlight clients.
        /// </summary>
        private const string UniqueId = "0123456789ABCDEF";

        private static readonly ConcurrentDictionary<Type, XmlSerializer> XmlSerializers =
            new ConcurrentDictionary<Type, XmlSerializer>();

        private readonly HttpClient httpClient;

        private readonly X509Certificate2 certificate;

        private readonly Uri baseUrlHttp;

        private readonly Uri baseUrlHttps;

        private readonly BouncyCastleCryptographyManager cryptographyManager;

        public HttpGfeClient(X509Certificate2 certificate)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            this.certificate = certificate;

            HttpClientHandler httpClientHandler = new HttpClientHandler();
            httpClientHandler.ServerCertificateCustomValidationCallback = (a, b, c, d) => true;
            httpClientHandler.ClientCertificates.Add(certificate);

            this.httpClient = new HttpClient(httpClientHandler);
        }

        public async Task<Result<ServerInfoResponse>> GetServerInfoAsync()
        {
            // Attempt to request server info over HTTPs. This will not work if the machine
            // is not already paired but returns more info.
            Result<ServerInfoResponse> result = await this.DoGetRequestAsync<ServerInfoResponse>(this.baseUrlHttps, "/serverinfo");
            if (!result.IsSuccess)
            {
                // If we couldn't do it over HTTPs, try again over HTTP.
                result = await this.DoGetRequestAsync<ServerInfoResponse>(this.baseUrlHttp, "/serverinfo");
            }

            return result;
        }

        public async Task<Result> PairAsync()
        {
            // Generate a random 4-digit PIN.
            string pin = new Random().Next(10000).ToString("D4");

            // Generate salt value.
            byte[] salt = this.cryptographyManager.GenerateRandomBytes(16);

            // Get PEM encoded certificate;
            byte[] pemCertificate = BouncyCastleCryptographyManager.GetPemEncodedCertificate(this.certificate);

            // Get the server certificate.
            string queryString =
                string.Format(
                    "deviceName=roth&updateState=1&phrase=getservercert&salt={0}&clientcert={1}",
                    BouncyCastleCryptographyManager.BytesToHex(salt),
                    BouncyCastleCryptographyManager.BytesToHex(pemCertificate));
            Result<PairResponse> result = await this.DoGetRequestAsync<PairResponse>(this.baseUrlHttp, "/pair", queryString);
            if (!result.IsSuccess || result.Value.Paired != 1)
            {
                return result;
            }

            if (string.IsNullOrWhiteSpace(result.Value.PlainCert))
            {
                // Attempting to pair while another device is pairing will cause GFE
                // to give an empty cert in the response.
                return Result.Failed((int)GfeErrorCode.PairingAlreadyInProgress, "Pairing already in progress");
            }

            // Parse the server certificate.
            BouncyCastleX509Certificate serverCertificate = this.cryptographyManager.ParseCertificate(result.Value.PlainCert);

            // Salt and hash pin and use it to create an AES cipher.
            byte[] saltedAndHashedPin = this.cryptographyManager.HashData(BouncyCastleCryptographyManager.SaltData(salt, pin));
            AesCipher cipher = new AesCipher(saltedAndHashedPin);

            // Generate a random challenge and encrypt it using AES.
            byte[] clientChallenge = this.cryptographyManager.GenerateRandomBytes(16);
            byte[] encryptedClientChallenge = cipher.Encrypt(clientChallenge);

            // Send the challenge to the server.
            queryString = $"devicename=roth&updateState=1&clientchallenge={BouncyCastleCryptographyManager.BytesToHex(encryptedClientChallenge)}";
            result = await this.DoGetRequestAsync<PairResponse>(this.baseUrlHttp, "/pair", queryString);
            if (!result.IsSuccess || result.Value.Paired != 1 || string.IsNullOrWhiteSpace(result.Value.ChallengeResponse))
            {
                return result;
            }

            // Decrypt and parse the server's challenge response and subsequent challenge.
            byte[] decryptedServerChallengeResponse = cipher.Decrypt(BouncyCastleCryptographyManager.HexToBytes(result.Value.ChallengeResponse));
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
                        BouncyCastleCryptographyManager.GetCertificateSignature(this.certificate), 
                        clientSecret));
            byte[] encryptedChallengeResponse = cipher.Encrypt(challengeResponseHash);

            // Send the challenge response to the server.
            queryString = $"devicename=roth&updateState=1&serverchallengeresp={BouncyCastleCryptographyManager.BytesToHex(encryptedChallengeResponse)}";
            result = await this.DoGetRequestAsync<PairResponse>(this.baseUrlHttp, "/pair", queryString);
            if (!result.IsSuccess || result.Value.Paired != 1 || string.IsNullOrWhiteSpace(result.Value.PairingSecret))
            {
                return result;
            }

            // Get the server's signed secret.
            byte[] serverSecretResponse = BouncyCastleCryptographyManager.HexToBytes(result.Value.PairingSecret);
            byte[] serverSecret = new byte[16];
            byte[] serverSignature = new byte[256];
            Array.Copy(serverSecretResponse, serverSecret, serverSecret.Length);
            Array.Copy(serverSecretResponse, serverSecret.Length, serverSignature, 0, serverSignature.Length);

            // Ensure the authenticity of the data.
            if (!this.cryptographyManager.VerifySignature(serverSecret, serverSignature, serverCertificate))
            {
                return Result.Failed((int)GfeErrorCode.PairingInvalidSignature, "Pairing failed with invalid signature.");
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
                return Result.Failed((int)GfeErrorCode.PairingIncorrectPin, "Pairing failed with incorrect PIN.");
            }

            // Create our signed secret.
            byte[] signedSecret = this.cryptographyManager.SignData(clientSecret, this.certificate.PrivateKey);
            byte[] clientPairingSecret = 
                BouncyCastleCryptographyManager.ConcatenateByteArrays(
                    clientSecret,
                    signedSecret);

            // Send it to the server.
            queryString = $"devicename=roth&updateState=1&clientpairingsecret={BouncyCastleCryptographyManager.BytesToHex(clientPairingSecret)}";
            result = await this.DoGetRequestAsync<PairResponse>(this.baseUrlHttp, "/pair", queryString);
            if (!result.IsSuccess || result.Value.Paired != 1)
            {
                return result;
            }

            // Do the initial challenge (seems neccessary for us to show as paired). Note that
            // this must be done over HTTPs.
            result = 
                await this.DoGetRequestAsync<PairResponse>(
                    this.baseUrlHttps, 
                    "/pair", 
                    "devicename=roth&updateState=1&phrase=pairchallenge");
            if (!result.IsSuccess || result.Value.Paired != 1)
            {
                return result;
            }

            return Result.Succeeded();
        }

        public Task GetAppListAsync()
        {
            return this.DoGetRequestAsync<string>(this.baseUrlHttps, "/applist");
        }

        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        private Task<Result<TResponse>> DoGetRequestAsync<TResponse>(Uri baseUri, string resourcePath) where TResponse : class
        {
            return this.DoGetRequestAsync<TResponse>(baseUri, resourcePath, null);
        }

        private async Task<Result<TResponse>> DoGetRequestAsync<TResponse>(
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
                        return 
                            Result<TResponse>.Failed(
                                (int)GfeErrorCode.HttpError, 
                                $"HTTP request to {requestUrl} failed with error code {response.StatusCode}.");
                    }

                    XmlSerializer serializer = XmlSerializers.GetOrAdd(
                        typeof(TResponse),
                        (type) => new XmlSerializer(type));
                    TResponse responseObject = serializer.Deserialize(await response.Content.ReadAsStreamAsync()) as TResponse;

                    return Result<TResponse>.Succeeded(responseObject);
                }
            }
            catch (Exception e)
            {
                // Log?
                return Result<TResponse>.Failed((int)GfeErrorCode.UnknownError, e);
            }
        }

        private void Dispose(bool disposing)
        {
            if (disposing)
            {
                this.httpClient.Dispose();
            }
        }
    }
}
