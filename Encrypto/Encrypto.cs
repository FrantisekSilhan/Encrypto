using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Encryptons
{
    internal class Encrypto
    {
        // main
        public string PrivateKey { get; private set; }
        public string PublicKey { get; private set; }
        public Encrypto()
        {
            RSA rsa = RSA.Create();
            PublicKey = ByteArrayToHexString(rsa.ExportRSAPublicKey());
            PrivateKey = ByteArrayToHexString(rsa.ExportRSAPrivateKey());
            rsa.Dispose();
        }

        // static functions
        public static string ByteArrayToHexString(byte[] byteArray)
        {
            return BitConverter.ToString(byteArray).Replace("-", "");
        }
        public static byte[] HexStringToByteArray(string hexString)
        {
            int length = hexString.Length;
            byte[] byteArray = new byte[length / 2];
            for (int i = 0; i < length; i += 2)
            {
                byteArray[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            }
            return byteArray;
        }
        public static string Encrypt(string s, string key)
        {
            try
            {
                byte[] original = Encoding.UTF8.GetBytes(s);
                RSA rsa = RSA.Create();
                rsa.ImportRSAPublicKey(HexStringToByteArray(key), out _);
                string encrypted = ByteArrayToHexString(rsa.Encrypt(original, RSAEncryptionPadding.OaepSHA256));
                rsa.Dispose();

                return encrypted;
            }
            catch
            {
                throw new Exception("Oops! Something went wrong while trying to encrypt the string. Please ensure that you are using the correct public key and try again.");
            }
        }
        public static string Sign(string s, string key)
        {
            try
            {
                byte[] original = Encoding.UTF8.GetBytes(s);
                RSA rsa = RSA.Create();
                rsa.ImportRSAPrivateKey(HexStringToByteArray(key), out _);
                string signature = ByteArrayToHexString(rsa.SignData(original, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
                rsa.Dispose();

                return signature;
            }
            catch
            {
                throw new Exception("Oops! Something went wrong while trying to sign the string. Please ensure that you are using the correct private key and try again.");
            }
        }
        public static bool VerifySignature(string s, string signature, string key)
        {
            try
            {
                byte[] original = Encoding.UTF8.GetBytes(s);
                RSA rsa = RSA.Create();
                rsa.ImportRSAPublicKey(HexStringToByteArray(key), out _);
                bool verifiedSignature = (bool)rsa.VerifyData(original, HexStringToByteArray(signature), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                rsa.Dispose();
                return verifiedSignature;
            }
            catch
            {
                throw new Exception("Oops! Something went wrong while trying to verify the signature. Please ensure that you are using the correct public key and try again.");
            }
        }
        public static string Decrypt(string s, string key)
        {
            try
            {
                RSA rsa = RSA.Create();
                rsa.ImportRSAPrivateKey(HexStringToByteArray(key), out _);
                string decrypted = Encoding.UTF8.GetString(rsa.Decrypt(HexStringToByteArray(s), RSAEncryptionPadding.OaepSHA256));
                rsa.Dispose();

                return decrypted;
            }
            catch
            {
                throw new Exception("Oops! Something went wrong while trying to decrypt the string. Please ensure that you are using the correct private key and try again.");
            }

        }
        public static string GetMessageFromArgsOrFile(string messageArg)
        {
            if (File.Exists(messageArg))
            {
                return File.ReadAllText(messageArg);
            }
            else
            {
                return messageArg;
            }
        }

        // functions
        public void GenerateNewKeys()
        {
            RSA rsa = RSA.Create();
            PublicKey = ByteArrayToHexString(rsa.ExportRSAPublicKey());
            PrivateKey = ByteArrayToHexString(rsa.ExportRSAPrivateKey());
            rsa.Dispose();
        }
        public void SavePrivateKeyToFile(string fileName)
        {
            File.WriteAllText(fileName, PrivateKey);
        }
        public void SavePublicKeyToFile(string fileName)
        {
            File.WriteAllText(fileName, PublicKey);
        }
        public void LoadPrivateKeyFromFile(string fileName)
        {
            RSA rsa = RSA.Create();
            PrivateKey = File.ReadAllText(fileName);
            try
            {
                rsa.ImportRSAPrivateKey(HexStringToByteArray(PrivateKey), out int bytesRead);
                Console.WriteLine($"private key loaded ({bytesRead} bytes)");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error importing private key: {ex.Message}");
            }
            rsa.Dispose();
        }
        public void LoadPublicKeyFromFile(string fileName)
        {
            RSA rsa = RSA.Create();
            PublicKey = File.ReadAllText(fileName);
            try
            {
                rsa.ImportRSAPublicKey(HexStringToByteArray(PublicKey), out int bytesRead);
                Console.WriteLine($"public key loaded ({bytesRead} bytes)");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error importing public key: {ex.Message}");
            }
            rsa.Dispose();
        }
    }
}
