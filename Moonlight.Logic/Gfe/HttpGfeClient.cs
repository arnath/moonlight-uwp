namespace Moonlight.Xbox.Logic.Gfe
{
    using System;
    using System.Collections.Concurrent;
    using System.Net.Http;
    using System.Threading.Tasks;
    using System.Xml.Serialization;

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

        private readonly Uri baseUrlHttp;

        private readonly Uri baseUrlHttps;

        public Task<ServerInfoResponse> GetServerInfo()
        {
            return this.DoGetRequestAsync<ServerInfoResponse>(
                this.baseUrlHttps,
                "/serverinfo");
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
