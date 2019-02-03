namespace Moonlight.Xbox.Logic.Gfe
{
    using System.Xml.Serialization;

    [XmlRoot("root")]
    public class PairResponse
    {
        [XmlElement("challengeresponse")]
        public string ChallengeResponse { get; set; }

        [XmlElement("encodedcipher")]
        public string EncodedCipher { get; set; }

        [XmlElement("isBusy")]
        public bool IsBusy { get; set; }

        [XmlElement("paired")]
        public int Paired { get; set; }

        [XmlElement("pairingsecret")]
        public string PairingSecret { get; set; }

        [XmlElement("plaincert")]
        public string PlainCert { get; set; }
    }
}
