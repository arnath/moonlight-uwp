namespace Moonlight.Xbox.Logic.Gfe
{
    using System.Xml.Serialization;

    [XmlRoot("root")]
    public class ServerInfoResponse
    {
        [XmlElement("hostname")]
        public string HostName { get; set; }

        [XmlElement("uuid")]
        public string Uuid { get; set; }

        [XmlElement("mac")]
        public string MacAddress { get; set; }

        [XmlElement("LocalIP")]
        public string LocalAddress { get; set; }

        [XmlElement("RemoteIP")]
        public string RemoteAddress { get; set; }

        [XmlElement("PairStatus")]
        public int PairStatus { get; set; }
    }
}
