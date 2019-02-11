using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Serialization;
using System.Windows;
using System.IO;
using System.ComponentModel;
using Org.BouncyCastle;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;


namespace Projekt_AES
{
    public class Encryptor
    {
        public List<string> Users { get; set; }
        public byte[] InitialVector { get; set; }
        public int KeySize { get; set; }
        public string Mode { get; set; }
        public int SubblockSize { get; set; }

        public delegate void ProgressUpdate(int value);
        public event ProgressUpdate EncryptProgress;
        public delegate void WorkCompleted(int result, string message, bool forEncryption);
        public event WorkCompleted EncryptCompleted;
        public BackgroundWorker bw; //do osobnego watku, zeby nie bylo zwiechy calej apki przy szfyrowaniu

        public Encryptor (string mode, int key, int block, List<string> users)
        {
            Mode = mode;
            KeySize = key;
            SubblockSize = block;
            Users = users;
            
            bw = new BackgroundWorker();
            bw.WorkerReportsProgress = true;
            bw.WorkerSupportsCancellation = true;
            bw.DoWork += new DoWorkEventHandler(StartEncrypt);
            bw.RunWorkerCompleted += new RunWorkerCompletedEventHandler(EncryptionCompleted);
            
        }

        private void StartEncrypt(object sender, DoWorkEventArgs e)
        {
            var sessionKey = GenerateSessionKey(KeySize);
            CreateXMLFile(sessionKey);
            EncryptToFile(sessionKey);  
        }

        private void EncryptionCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            if (e.Error != null)
            {
                if (EncryptCompleted != null)
                {
                    EncryptCompleted(-1, "BŁĄD SZYFROWNIA!!!", true);
                };
            }
  
            else
            {
                if (EncryptCompleted != null)
                {
                    EncryptCompleted(0, "PLIK ZASZYFROWANY!!!", true);
                }
            }


        }

        public static byte[] GenerateSessionKey(int length)
        {
            using (RandomNumberGenerator randomNumberGenerator = new RNGCryptoServiceProvider())
            {
                byte[] sessionKey = new byte[length / 8];
                randomNumberGenerator.GetBytes(sessionKey);
                return sessionKey;
            }
        }
        public byte[] EncryptSessionKey (byte[] key, string user)
        {

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                try
                {
                    var rsaInfo = File.ReadAllText(@"C:\Users\ruchn\OneDrive\Obrazy\Public\" + user + ".txt");
                    rsa.FromXmlString(rsaInfo);

                    return rsa.Encrypt(key, false);
                }
                catch (Exception)
                {
                    MessageBox.Show("BLAD KODOWANIA KLUCZA SESYJNEGO!!!!");
                    return null;
                }
            }       
        }

        public void CreateInitialVector()
        {
            Random random = new Random();
           
            var aes = new RC6Engine();
            InitialVector = new byte[aes.GetBlockSize()];
            random.NextBytes(InitialVector);
        }

        public void CreateXMLFile (byte[] key) //key - klucz sesyjny
        {
            File.Delete(MainWindow.OutputFile);
            XDocument xml = new XDocument(
                new XElement("EncryptedFileHeader",
                    new XElement("Algorithm", "AES"),
                    new XElement("KeySize", KeySize.ToString()),
                    new XElement("BlockSize", "128"),
                    new XElement("CipherMode", Mode)));

            if (Mode == "OFB" || Mode == "CFB")
                xml.Root.Add(new XElement("SubblockSize", SubblockSize.ToString()));

            if (Mode != "ECB")
            {
                CreateInitialVector();
                xml.Root.Add(new XElement("IV", Convert.ToBase64String(InitialVector)));
            }

            xml.Root.Add(new XElement("ApprovedUsers"));

            var usr = xml.Root.Element("ApprovedUsers");

            foreach (var u in Users)
            {
                var encodedKey = EncryptSessionKey(key, u); //zaszyfrowany klucz sesyjny kluczem publicznym odbiorcy
                usr.Add(new XElement("User",
                    new XElement("Name", u),
                    new XElement("SessionKey", Convert.ToBase64String(encodedKey))));
            }

            xml.Save(MainWindow.OutputFile);
        }

        public void EncryptToFile (byte[] sessionKey)
        {
            File.AppendAllText(MainWindow.OutputFile, Environment.NewLine);

            using (var input = File.Open(MainWindow.InputFile, FileMode.Open))
            using (var fs = File.Open(MainWindow.OutputFile, FileMode.Append))
            {
                
                PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(new RC6Engine());
                   
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

                    case "CBC" :
                        {
                            
                            CbcBlockCipher cipher = new CbcBlockCipher(new RC6Engine());
                            aes = new PaddedBufferedBlockCipher(cipher);
                            break;
                        }

                    case "ECB":
                        {
                                 
                           aes = new PaddedBufferedBlockCipher(new RC6Engine());
                           aes.Init(true, new KeyParameter(sessionKey));
                           break;
                           
                        }             
                }
                

                if (Mode != "ECB")
                {
                  
                    var keyParameter = new KeyParameter(sessionKey);
                    var parameters = new ParametersWithIV(keyParameter, InitialVector);
                    aes.Init(true, parameters);
                }

                
                var buffer = new byte[aes.GetBlockSize()];
                var outputBuffer = new byte[aes.GetBlockSize() + aes.GetOutputSize(buffer.Length)];

                int inCount = 0;
                int outCount = 0;

                
                long blocksCounter = input.Length / buffer.Length + 1;
                long i = 0;
                float percent;

                while((inCount = input.Read(buffer,0,buffer.Length)) > 0)
                {               
                    outCount = aes.ProcessBytes(buffer, 0, inCount, outputBuffer, 0);
                    fs.Write(outputBuffer, 0, outCount);
                    i++;

                    if (EncryptProgress != null)
                    {
                        percent = (float)i / blocksCounter * 100;
                        EncryptProgress((int)percent);
                    }

                }

                outCount = aes.DoFinal(outputBuffer, 0);
                fs.Write(outputBuffer, 0, outCount);
            }
        }
    }

    public class Backgroundworker
    {
    }
}
