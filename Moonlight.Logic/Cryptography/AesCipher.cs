namespace Moonlight.Xbox.Logic.Cryptography
{
    using System;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Security;

    public class AesCipher
    {
        private const int KeyLength = 16;

        private readonly ICipherParameters key;

        private readonly IBufferedCipher cipher;

        public AesCipher(byte[] keyData)
        {
            this.key = new KeyParameter(keyData, 0, KeyLength);
            this.cipher = CipherUtilities.GetCipher("AES/ECB/NoPadding");
        }

        public byte[] Encrypt(byte[] data)
        {
            return this.DoAesCipher(true, data);
        }

        public byte[] Decrypt(byte[] data)
        {
            return this.DoAesCipher(false, data);
        }

        private byte[] DoAesCipher(bool encrypt, byte[] data)
        {
            int blockRoundedSize = ((data.Length + 15) / 16) * 16;
            byte[] blockRoundedData = new byte[blockRoundedSize];
            Array.Copy(data, blockRoundedData, blockRoundedSize);

            this.cipher.Init(encrypt, this.key);
            return this.cipher.DoFinal(blockRoundedData);
        }
    }
}
