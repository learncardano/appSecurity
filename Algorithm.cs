using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace appSecurity
{
    /// <summary>
    /// Based on https://msdn.microsoft.com/en-us/library/system.security.cryptography.rijndaelmanaged(v=vs.110).aspx
    /// Uses UTF8 Encoding http://security.stackexchange.com/a/90850
    /// </summary>
    public class AnotherAES : IDisposable
    {
        private RijndaelManaged rijn;

        /// <summary>
        /// Initialize algo with key, block size, key size, padding mode and cipher mode to be known.
        /// </summary>
        /// <param name="key">ASCII key to be used for encryption or decryption</param>
        /// <param name="blockSize">block size to use for AES algorithm. 128, 192 or 256 bits</param>
        /// <param name="keySize">key length to use for AES algorithm. 128, 192, or 256 bits</param>
        /// <param name="paddingMode"></param>
        /// <param name="cipherMode"></param>
        public AnotherAES(string key, int blockSize, int keySize, PaddingMode paddingMode, CipherMode cipherMode)
        {
            rijn = new RijndaelManaged();
            rijn.Key = Encoding.UTF8.GetBytes(key);
            rijn.BlockSize = blockSize;
            rijn.KeySize = keySize;
            rijn.Padding = paddingMode;
            rijn.Mode = cipherMode;
        }

        /// <summary>
        /// Initialize algo just with key
        /// Defaults for RijndaelManaged class: 
        /// Block Size: 256 bits (32 bytes)
        /// Key Size: 128 bits (16 bytes)
        /// Padding Mode: PKCS7
        /// Cipher Mode: CBC
        /// </summary>
        /// <param name="key"></param>
        public AnotherAES(string key)
        {
            rijn = new RijndaelManaged();
            byte[] keyArray = Encoding.UTF8.GetBytes(key);
            rijn.Key = keyArray;
        }

        /// <summary>
        /// Based on https://msdn.microsoft.com/en-us/library/system.security.cryptography.rijndaelmanaged(v=vs.110).aspx
        /// Encrypt a string using RijndaelManaged encryptor.
        /// </summary>
        /// <param name="plainText">string to be encrypted</param>
        /// <param name="IV">initialization vector to be used by crypto algorithm</param>
        /// <returns></returns>
        public byte[] Encrypt(string plainText, byte[] IV)
        {
            if (rijn == null)
                throw new ArgumentNullException("Provider not initialized");

            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText cannot be null or empty");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV cannot be null or empty");
            byte[] encrypted;

            // Create a decrytor to perform the stream transform.
            using (ICryptoTransform encryptor = rijn.CreateEncryptor(rijn.Key, IV))
            {
                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        /// <summary>
        /// Based on https://msdn.microsoft.com/en-us/library/system.security.cryptography.rijndaelmanaged(v=vs.110).aspx
        /// </summary>
        /// <param name="cipherText">bytes to be decrypted back to plaintext</param>
        /// <param name="IV">initialization vector used to encrypt the bytes</param>
        /// <returns></returns>
        public string Decrypt(byte[] cipherText, byte[] IV)
        {
            if (rijn == null)
                throw new ArgumentNullException("Provider not initialized");

            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText cannot be null or empty");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV cannot be null or empty");

            // Declare the string used to hold the decrypted text.
            string plaintext = null;

            // Create a decrytor to perform the stream transform.
            using (ICryptoTransform decryptor = rijn.CreateDecryptor(rijn.Key, IV))
            {
                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        /// <summary>
        /// Generates a unique encryption vector using RijndaelManaged.GenerateIV() method
        /// </summary>
        /// <returns></returns>
        public byte[] GenerateEncryptionVector()
        {
            if (rijn == null)
                throw new ArgumentNullException("Provider not initialized");

            //Generate a Vector
            rijn.GenerateIV();
            return rijn.IV;
        }

        /// <summary>
        /// Based on https://stackoverflow.com/a/1344255
        /// Generate a unique string given number of bytes required.
        /// This string can be used as IV. IV byte size should be equal to cipher-block byte size. 
        /// Allows seeing IV in plaintext so it can be passed along a url or some message.
        /// </summary>
        /// <param name="numBytes"></param>
        /// <returns></returns>
        public static string GetUniqueString(int numBytes)
        {
            char[] chars = new char[62];
            chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();
            byte[] data = new byte[1];
            using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider())
            {
                data = new byte[numBytes];
                crypto.GetBytes(data);
            }
            StringBuilder result = new StringBuilder(numBytes);
            foreach (byte b in data)
            {
                result.Append(chars[b % (chars.Length)]);
            }
            return result.ToString();
        }

        /// <summary>
        /// Converts a string to byte array. Useful when converting back hex string which was originally formed from bytes.
        /// </summary>
        /// <param name="hex"></param>
        /// <returns></returns>
        public static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        /// <summary>
        /// Dispose RijndaelManaged object initialized in the constructor
        /// </summary>
        public void Dispose()
        {
            if (rijn != null)
                rijn.Dispose();
        }
    }

    public class Algorithm
    {
        // ===========================================================================================
        // Class library for encrypting text.
        //
        // Must add reference via NuGet:
        // - System.Security.Cryptography.Cng
        // ===========================================================================================
        public class AAES
        {
            private static String key;

            public static String Key
            {
                get { return key; }
                set { key = value; }
            }

            public AAES(String Key)
            {
                key = Key;
            }

            public String Encrypt(String textToEncrypt)
            {
                string hex = string.Empty;
                string ivString = AnotherAES.GetUniqueString(16);
                using (AnotherAES aes = new AnotherAES(key))
                {
                    //encrypting side
                    byte[] IV = Encoding.UTF8.GetBytes(ivString);

                    //get encrypted bytes (IV bytes prepended to cipher bytes)
                    byte[] encryptedBytes = aes.Encrypt(textToEncrypt, IV);
                    byte[] encryptedBytesWithIV = IV.Concat(encryptedBytes).ToArray();

                    //get hex string to send with url
                    //this hex has both IV and ciphertext
                    hex = BitConverter.ToString(encryptedBytesWithIV).Replace("-", "");
                }

                return hex;
            }

            public string Decrypt(String textToDecrypt)
            {
                string roundTrip = string.Empty;
                using (AnotherAES aes = new AnotherAES(key))
                {
                    //get bytes from url
                    byte[] encryptedBytesWithIV = AnotherAES.StringToByteArray(textToDecrypt);
                    byte[] IV = encryptedBytesWithIV.Take(16).ToArray();
                    byte[] cipher = encryptedBytesWithIV.Skip(16).ToArray();

                    roundTrip = aes.Decrypt(cipher, IV);
                }
                return roundTrip;
            }
        }

        public class DES
        {
            private static String key = "LT_125018022022$";

            public String Encrypt(String textToEncrypt)
            {
                return Encrypt(textToEncrypt, key);
            }

            public String Encrypt(String textToEncrypt, String key)
            {
                byte[] inputArray = UTF8Encoding.UTF8.GetBytes(textToEncrypt);
                TripleDESCryptoServiceProvider tripleDES = new TripleDESCryptoServiceProvider();
                tripleDES.Key = UTF8Encoding.UTF8.GetBytes(key);
                tripleDES.Mode = CipherMode.ECB;
                tripleDES.Padding = PaddingMode.PKCS7;
                ICryptoTransform cTransform = tripleDES.CreateEncryptor();
                byte[] resultArray = cTransform.TransformFinalBlock(inputArray, 0, inputArray.Length);
                tripleDES.Clear();
                return Convert.ToBase64String(resultArray, 0, resultArray.Length);
            }

            public String Decrypt(String textToDecrypt)
            {
                return Decrypt(textToDecrypt, key);
            }

            public String Decrypt(String textToDecrypt, String key)
            {
                byte[] inputArray = Convert.FromBase64String(textToDecrypt);
                TripleDESCryptoServiceProvider tripleDES = new TripleDESCryptoServiceProvider();
                tripleDES.Key = UTF8Encoding.UTF8.GetBytes(key);
                tripleDES.Mode = CipherMode.ECB;
                tripleDES.Padding = PaddingMode.PKCS7;
                ICryptoTransform cTransform = tripleDES.CreateDecryptor();
                byte[] resultArray = cTransform.TransformFinalBlock(inputArray, 0, inputArray.Length);
                tripleDES.Clear();
                return UTF8Encoding.UTF8.GetString(resultArray);
            }
        }

        public class SHA
        {
            static String Hash(String textToHash, string salt = "")
            {
                if (String.IsNullOrEmpty(textToHash))
                {
                    return String.Empty;
                }

                // Uses SHA256 to create the hash
                using (var sha = new System.Security.Cryptography.SHA256Managed())
                {
                    // Convert the string to a byte array first, to be processed
                    byte[] textBytes = System.Text.Encoding.UTF8.GetBytes(textToHash + salt);
                    byte[] hashBytes = sha.ComputeHash(textBytes);

                    // Convert back to a string, removing the '-' that BitConverter adds
                    string hash = BitConverter
                        .ToString(hashBytes)
                        .Replace("-", String.Empty);

                    return hash;
                }
            }
        }

        public class RSA
        {
            static UnicodeEncoding ByteConverter = new UnicodeEncoding();
            static RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            static byte[] plainText, encryptedText, decryptedText;

            public String Encrypt(String textToEncrypt)
            {
                plainText = ByteConverter.GetBytes(textToEncrypt);
                encryptedText = Encryption(plainText, rsa.ExportParameters(false), false);

                return ByteConverter.GetString(encryptedText);
            }

            public String Decrypt(String textToDecrypt)
            {
                decryptedText = Decryption(ByteConverter.GetBytes(textToDecrypt),
                    rsa.ExportParameters(true), false);

                return ByteConverter.GetString(decryptedText);
            }

            private byte[] Encryption(byte[] Data, RSAParameters RSAKey, bool DoOAEPPadding)
            {
                try
                {
                    byte[] encryptedData;
                    using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                    {
                        rsa.ImportParameters(RSAKey);
                        encryptedData = rsa.Encrypt(Data, DoOAEPPadding);
                    }
                    return encryptedData;
                }
                catch
                {
                    return null;
                }
            }

            private byte[] Decryption(byte[] Data, RSAParameters RSAKey, bool DoOAEPPadding)
            {
                try
                {
                    byte[] decryptedData;
                    using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                    {
                        rsa.ImportParameters(RSAKey);
                        decryptedData = rsa.Decrypt(Data, DoOAEPPadding);
                    }
                    return decryptedData;
                }
                catch
                {
                    return null;
                }
            }
        }

        public class MD5
        {
            public String Hash(String textToHash)
            {
                HMACMD5 hMACMD5 = new HMACMD5();

                // Compute hash from the bytes generated from textToHash  
                hMACMD5.ComputeHash(ASCIIEncoding.ASCII.GetBytes(textToHash));

                // Get result after computing the hash
                byte[] hash = hMACMD5.Hash;

                StringBuilder str = new StringBuilder();
                for (int i = 0; i < hash.Length; i++)
                {
                    // Change each byte into 2 hexadecimal digits
                    str.Append(hash[i].ToString("x2"));
                }

                return str.ToString();
            }
        }
    }
}