namespace Moonlight.Xbox
{
    using System.Security.Cryptography.X509Certificates;
    using Windows.UI.Xaml;
    using Windows.UI.Xaml.Controls;
    using Moonlight.Xbox.Logic;

    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        private readonly BouncyCastleCryptographyManager cryptographyManager;

        public MainPage()
        {
            this.InitializeComponent();
            this.cryptographyManager = new BouncyCastleCryptographyManager();
        }

        private async void CreateCertificateButton_Click(object sender, RoutedEventArgs e)
        {
            X509Certificate2 certificate = await this.cryptographyManager.CreateHttpsCertificateAsync();
            outputTextBlock.Text = $"Certificate created successfully. Friendly name: {certificate.FriendlyName}.";
        }

        private async void GetCertificateButton_Click(object sender, RoutedEventArgs e)
        {
            X509Certificate2 certificate = await this.cryptographyManager.GetHttpsCertificateAsync();
            if (certificate == null)
            {
                outputTextBlock.Text = "No certificate found";
            }
            else
            {
                outputTextBlock.Text = $"Found certificate. Friendly name: {certificate.FriendlyName}.";
            }
        }
    }
}
