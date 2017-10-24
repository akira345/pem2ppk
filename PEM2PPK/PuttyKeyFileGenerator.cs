using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
//https://antonymale.co.uk/generating-putty-key-files.htmlより一部修正

namespace PEM2PPK
{
    public class PuttyKeyFileGenerator
    {
        private const int prefixSize = 4;
        private const int paddedPrefixSize = prefixSize + 1;
        private const int lineLength = 64;
        private const string keyType = "ssh-rsa";
        private const string encryptionType = "none";

        public static string RSAToPuttyPrivateKey(RSAParameters keyParameters, string comment = "imported-openssh-key")
        {
            //RSACryptoServiceProvider からRSAParametersに変更
            //RSAParameters keyParameters = cryptoServiceProvider.ExportParameters(includePrivateParameters: true);

            byte[] publicBuffer = new byte[3 + keyType.Length + paddedPrefixSize + keyParameters.Exponent.Length +
                                           paddedPrefixSize + keyParameters.Modulus.Length + 1];

            using (var writer = new BinaryWriter(new MemoryStream(publicBuffer)))
            {
                writer.Write(new byte[] { 0x00, 0x00, 0x00 });
                writer.Write(keyType);
                WritePrefixed(writer, keyParameters.Exponent, true);
                WritePrefixed(writer, keyParameters.Modulus, true);
            }
            string publicBlob = Convert.ToBase64String(publicBuffer);

            byte[] privateBuffer = new byte[paddedPrefixSize + keyParameters.D.Length + paddedPrefixSize + keyParameters.P.Length +
                                            paddedPrefixSize + keyParameters.Q.Length + paddedPrefixSize + keyParameters.InverseQ.Length];

            using (var writer = new BinaryWriter(new MemoryStream(privateBuffer)))
            {
                WritePrefixed(writer, keyParameters.D, true);
                WritePrefixed(writer, keyParameters.P, true);
                WritePrefixed(writer, keyParameters.Q, true);
                WritePrefixed(writer, keyParameters.InverseQ, true);
            }
            string privateBlob = Convert.ToBase64String(privateBuffer);

            byte[] bytesToHash = new byte[prefixSize + keyType.Length + prefixSize + encryptionType.Length + prefixSize + comment.Length +
                                          prefixSize + publicBuffer.Length + prefixSize + privateBuffer.Length];

            using (var writer = new BinaryWriter(new MemoryStream(bytesToHash)))
            {
                WritePrefixed(writer, Encoding.ASCII.GetBytes(keyType));
                WritePrefixed(writer, Encoding.ASCII.GetBytes(encryptionType));
                WritePrefixed(writer, Encoding.ASCII.GetBytes(comment));
                WritePrefixed(writer, publicBuffer);
                WritePrefixed(writer, privateBuffer);
            }

            var hmacsha1 = new HMACSHA1(new SHA1CryptoServiceProvider().ComputeHash(Encoding.ASCII.GetBytes("putty-private-key-file-mac-key")));
            string hash = String.Join("", hmacsha1.ComputeHash(bytesToHash).Select(x => String.Format("{0:x2}", x)));

            var sb = new StringBuilder();
            sb.AppendLine("PuTTY-User-Key-File-2: " + keyType);
            sb.AppendLine("Encryption: " + encryptionType);
            sb.AppendLine("Comment: " + comment);

            var publicLines = SpliceText(publicBlob, lineLength).ToArray();
            sb.AppendLine("Public-Lines: " + publicLines.Length);
            foreach (var line in publicLines)
            {
                sb.AppendLine(line);
            }

            var privateLines = SpliceText(privateBlob, lineLength).ToArray();
            sb.AppendLine("Private-Lines: " + privateLines.Length);
            foreach (var line in privateLines)
            {
                sb.AppendLine(line);
            }

            sb.AppendLine("Private-MAC: " + hash);

            return sb.ToString();
        }

        private static void WritePrefixed(BinaryWriter writer, byte[] bytes, bool addLeadingNull = false)
        {
            var length = bytes.Length;
            if (addLeadingNull)
                length++;

            writer.Write(BitConverter.GetBytes(length).Reverse().ToArray());
            if (addLeadingNull)
                writer.Write((byte)0x00);
            writer.Write(bytes);
        }

        private static IEnumerable<string> SpliceText(string text, int length)
        {
            for (int i = 0; i < text.Length; i += length)
            {
                yield return text.Substring(i, Math.Min(length, text.Length - i));
            }
        }
    }
}
