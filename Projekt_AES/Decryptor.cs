using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using System.IO;
using System.Windows;
using Org.BouncyCastle;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using System.ComponentModel;
using Org.BouncyCastle.Crypto;

namespace Projekt_AES
{
   public class Decryptor
    {
        public string Mode { get; set; }
        public int KeySize { get; set; }
        public int SubblockSize { get; set; }
        public sbyte[] Cryptogram { get; set; }
        public string Username { get; set; }
        public byte[] EncodedKey { get; set; }
        public byte[] PasswordHash = new byte[24];
        public byte[] InitialVector { get; set; }
        private bool IsPasswordValid { get; set; }

        public delegate void ProgressUpdate(int value);
        public event ProgressUpdate DecryptProgress;
        public delegate void WorkCompleted(int result, string message, bool forEncryption);
        public event WorkCompleted DecryptCompleted;
        public BackgroundWorker bw;

        public Decryptor(string user, string password)
        {
            bw = new BackgroundWorker();
            bw.DoWork += new DoWorkEventHandler(StartDecrypt);
            bw.RunWorkerCompleted += new RunWorkerCompletedEventHandler(DecryptionCompleted);
            bw.WorkerSupportsCancellation = true;

            Username = user;
            IsPasswordValid = true;
            PasswordHash = Encoding.UTF8.GetBytes(User.GeneratePasswordShortcut(password));
            GetXMLFile(user, GetFileHeader());
        }

        private void DecryptionCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            if (e.Error != null)
            {
                if (DecryptCompleted != null)
                {
                    DecryptCompleted(-1, "BLAD DESZYFRACJI!!!", false);
                };
            }
           
            else
            {
                if (DecryptCompleted != null)
                {
                    DecryptCompleted(0, "PLIK ODSZYFROWANY!!!", false);
                }
            }
            File.Delete("zaszyfrowany.tmp");
        }

        private void StartDecrypt(object sender, DoWorkEventArgs e)
        {
            var sessionKey = DecryptSessionKey();
            GetCryptogram();
            DecryptFromFile(sessionKey);
        }

        public static string GetFileHeader()
        {
            string xmlString = "", line;
            using (var sr = new StreamReader(MainWindow.InputFile))
            {
                do
                {
                    line = sr.ReadLine();
                    xmlString += line;
                }
                while (!line.Contains("</ApprovedUsers>") && (!sr.EndOfStream));

                xmlString += "</EncryptedFileHeader>";
            }

            return xmlString;
        }

        public void GetXMLFile (string user, string xmlString)
        {
            try
            {
                var xml = XDocument.Parse(xmlString);
                var header = xml.Element("EncryptedFileHeader");

                KeySize = Int32.Parse(header.Element("KeySize").Value);
                Mode = header.Element("CipherMode").Value;

                if (header.Descendants("SubblockSize").Any()) 
                    SubblockSize = Int32.Parse(header.Element("SubblockSize").Value);

                if (header.Descendants("IV").Any())
                    InitialVector = Convert.FromBase64String(header.Element("IV").Value);

                var usr = header.Element("ApprovedUsers").Descendants("User").First(u => u.Element("Name").Value == user);

                var us = usr.Element("Name").Value;
                EncodedKey = Convert.FromBase64String(usr.Element("SessionKey").Value);
            }
            catch (Exception)
            {
                MessageBox.Show("ZŁY PLIK!!!");
            }
        }
      
        public void GetCryptogram()
        {
            byte[] buffer = new byte[1024];
            int bytesRead;

            using (var fs = File.Open("zaszyfrowany.tmp", FileMode.Create))
            using (var fs2 = File.Open(MainWindow.InputFile, FileMode.Open))
            using (var br = new BinaryReader(fs2))
            {
                string tmp = "";
                char c;
                while (true)
                {
                    c = br.ReadChar();
                    if (c == '\n')
                    {
                        if (tmp.Contains("</EncryptedFileHeader>")) break;
                        else
                            tmp = "";
                    }
                    else
                    {
                        tmp += c;
                    }
                }

                while ((bytesRead = br.Read(buffer, 0, buffer.Length)) > 0)
                {
                    fs.Write(buffer, 0, bytesRead);
                }
            }
        }

        public void DecryptFromFile (byte[] sessionKey)
        {
            using (var input = File.Open("zaszyfrowany.tmp", FileMode.Open))
            using (var fs = File.Open(MainWindow.OutputFile, FileMode.Create))
            {
                
                BufferedBlockCipher aes = new BufferedBlockCipher(new RC6Engine());

                if (IsPasswordValid)
                {
                    switch (Mode)
                    {
                        case "CFB":
                            {

                                CfbBlockCipher cipher = new CfbBlockCipher(new RC6Engine(), SubblockSize);
                                aes = new PaddedBufferedBlockCipher(cipher);
                                break;
                            }

                        case "OFB":
                            {

                                OfbBlockCipher cipher = new OfbBlockCipher(new RC6Engine(), SubblockSize);
                                aes = new PaddedBufferedBlockCipher(cipher);
                                break;
                            }

                        case "CBC":
                            {
                               
                                CbcBlockCipher cipher = new CbcBlockCipher(new RC6Engine());
                                aes = new PaddedBufferedBlockCipher(cipher);
                                break;
                            }

                        case "ECB":
                            {
                                
                                aes = new PaddedBufferedBlockCipher(new RC6Engine());
                                aes.Init(false, new KeyParameter(sessionKey));
                                break;
                            }
                    }

                    if (Mode != "ECB")
                    {
                       
                        var keyParam = new KeyParameter(sessionKey);
                        var parameters = new ParametersWithIV(keyParam, InitialVector);
                        aes.Init(false, parameters);
                    }
                }

                else
                {
                  
                    aes = new BufferedBlockCipher(new RC6Engine());
                    aes.Init(false, new KeyParameter(sessionKey));
                }
               
                var buffer = new byte[aes.GetBlockSize()];
                var outBuffer = new byte[aes.GetBlockSize() + aes.GetOutputSize(buffer.Length)];

                int inCount = 0;
                int outCount = 0;

                long blocksCounter = input.Length / buffer.Length + 1;
                long i = 0;
                float percent;

                while ((inCount = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    outCount = aes.ProcessBytes(buffer, 0, inCount, outBuffer, 0);
                    fs.Write(outBuffer, 0, outCount);
                    i++;

                    if (DecryptProgress != null)
                    {
                        percent = (float)i / blocksCounter * 100;
                        DecryptProgress((int)percent);
                    }
                }

                try
                {
                    
                    outCount = aes.DoFinal(outBuffer, 0);
                    fs.Write(outBuffer, 0, outCount);
                }
                catch (Exception)
                {
                    MessageBox.Show("BŁAD ZAPISU SZYFRU DO PLIKU!!!");
                }
            }
 
        }

        public byte[] DecryptSessionKey()
        {
            //odkodowanie z pliku(klucz = skrot hasla)          
            BufferedBlockCipher aes = new BufferedBlockCipher(new RC6Engine());
            aes.Init(true, new KeyParameter(PasswordHash));


            var privateKeyEncrypted = File.ReadAllBytes(@"C:\Users\ruchn\OneDrive\Obrazy\Private\" + Username + ".txt");
            var privateKey = new byte[aes.GetOutputSize(privateKeyEncrypted.Length)];
          
            var length = aes.ProcessBytes(privateKeyEncrypted, 0, privateKeyEncrypted.Length, privateKey, 0);
           
            aes.DoFinal(privateKey, length);
           

            var privateKeyToString = Encoding.UTF8.GetString(privateKey);

            //odkodowanie klucza sesyjnego kluczem prywatnym
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                try
                {
                    rsa.FromXmlString(privateKeyToString);
                    return rsa.Decrypt(EncodedKey, false);
                }
                catch (Exception)
                {
                    IsPasswordValid = false;
                    return PasswordHash.Take(KeySize / 8).ToArray();
                }
            }

        }
    }
}
