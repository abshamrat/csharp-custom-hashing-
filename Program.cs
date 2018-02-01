using System;
using static System.Console;
using System.IO;
using System.Text;
using System.Data;
using System.Data.SqlClient;
using System.Configuration;
using System.Security.Cryptography;

namespace Encryption
{
    class Program
    {
        static void Main(string[] args)
        {
            string line, text = "";
            string txtFilePath = @"c:\test.txt";
            System.IO.StreamReader file = new System.IO.StreamReader(txtFilePath);
            
            while ((line = file.ReadLine()) != null)
            {
                text += line;
            }

            file.Close();

            var watch = System.Diagnostics.Stopwatch.StartNew();
            // the code that you want to measure comes here
            var encTxt = Encrypt(text);
            watch.Stop();
            var elapsedMs = watch.ElapsedMilliseconds;
            Console.WriteLine(elapsedMs);
            Console.ReadKey();
        }
        private static string Encrypt(string textToEncrypt)
        {
            string EncryptionKey = "XH%/-+=";
            byte[] textBytes = Encoding.Unicode.GetBytes(textToEncrypt);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(textBytes, 0, textBytes.Length);
                        cs.Close();
                    }
                    textToEncrypt = Convert.ToBase64String(ms.ToArray());
                }
            }
            return textToEncrypt;
        }
        private static string Decrypt(string textToDecrypt)
        {
            string EncryptionKey = "XH%/-+=";
            byte[] textBytes = Convert.FromBase64String(textToDecrypt);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(textBytes, 0, textBytes.Length);
                        cs.Close();
                    }
                    textToDecrypt = Encoding.Unicode.GetString(ms.ToArray());
                }
            }
            return textToDecrypt;
        }
    }
}
