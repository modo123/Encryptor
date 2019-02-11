using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Security.Cryptography;
using System.Collections;
using Org.BouncyCastle;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Serialization;
using Org.BouncyCastle.Crypto;

namespace Projekt_AES
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        { 
            InitializeComponent();
        }
        Encryptor encryptor;
        Decryptor decryptor;

        public static string InputFile { get; set; }
        public static string OutputFile { get; set; }
        public string Login { get; set; }
        public string Password { get; set; }
        public List<User> Users { get; set; }
        
        
        private void ChooseFileClick(object sender, EventArgs e)
        { 
            var openFileDialog = new OpenFileDialog();
            openFileDialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyPictures);    
        
           
            if (openFileDialog.ShowDialog() == true)
            {
                try
                {
                    InputFile = openFileDialog.FileName;
                    if (Tabs.SelectedItem == EncryptionTab)
                    {
                        InputFilePathName.Content = InputFile; //przypisanie do labela sciezki
                    }
                 
                   else if (Tabs.SelectedItem == DecryptionTab)
                    {
                        DecInputFilePath.Content = openFileDialog.FileName;
                        lbUsersAllowed.Items.Clear();

                        var authorizedUsers = GetAuthorizedUsers();

                        if (authorizedUsers != null)
                        {
                            foreach (var u in authorizedUsers)
                            {
                                lbUsersAllowed.Items.Add(u);
                            }
                        }
                    }

            }
                catch (IOException)
                {
                    MessageBox.Show("BŁĄD PRZY WYBORZE PLIKU!!!");
                }  
            }
        }

        private void EncryptFileClick(object sender, RoutedEventArgs e)
        {

            if (!string.IsNullOrEmpty(InputFile) && (!string.IsNullOrEmpty(OutputFile)))
            {
                var users = RecipientsListBox.Items;
                if (users.Count > 0)
                {
                    var encryptMode = EncryptionMode.Text;
                    var keyLength = Int32.Parse(KeyLength.Text);
                    int blockLength = 0;

                    if (encryptMode == "CFB" || encryptMode == "OFB")
                        blockLength = Int32.Parse(SubBlockLength.Text);

                    var authorizedUsers = new List<string>();
                    foreach (var u in users)
                    {
                        authorizedUsers.Add(u.ToString());
                    }
                    
                    encryptor = new Encryptor(encryptMode, keyLength, blockLength, authorizedUsers);
                    encryptor.EncryptProgress += EncryptionProgress;
                    encryptor.EncryptCompleted += EncDecCompleted;           
                    encryptor.bw.RunWorkerAsync();
                }
                else
                {
                    MessageBox.Show("NIE WYBRANO ODBIORCOW!!!");
                }
            }
            else
            {
                MessageBox.Show("NIE WYBRALES PLIKU!!!");
            }
           
        }

        private void WriteFileClick(object sender, RoutedEventArgs e)
        {
                var sfd = new SaveFileDialog();
                 sfd.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyPictures);
                
                if (sfd.ShowDialog() == true)
                {
                    try
                    {
                        OutputFile = sfd.FileName;
                        if (Tabs.SelectedItem == EncryptionTab)
                        {
                            OutputFilePathName.Content = OutputFile; //przypisanie do labela sciezki
                        }
                        else if (Tabs.SelectedItem == DecryptionTab)
                        {
                            DecOutputFilePath.Content = sfd.FileName;
                        }
                    }
                    catch (IOException)
                    {
                        MessageBox.Show("BŁĄD WYBORU PLIKU!!!");
                    }
                 
            }
            
        }


        private void RegisterButtonClick(object sender, RoutedEventArgs e)
        {

            Login = UserNameRegister.Text;
            Password = PasswordRegister.Password.ToString();

            if (!string.IsNullOrEmpty(Login) && (!string.IsNullOrEmpty(Password)))
            {
                string publicPath = @"C:\Users\ruchn\OneDrive\Obrazy\Public\" + Login + ".txt";
                string privatePath = @"C:\Users\ruchn\OneDrive\Obrazy\Private\" + Login + ".txt";

                using (var rsa = new RSACryptoServiceProvider(2048))
                {
                    rsa.PersistKeyInCsp = false;
                    using (StreamWriter sw = File.CreateText(publicPath))
                    {
                        sw.Write(rsa.ToXmlString(false)); //klucz publiczny
                    }

                    using (var fs = File.Open(privatePath, FileMode.Append))
                    {
                        //skrot hasla
                        var passShortcut = Encoding.UTF8.GetBytes(User.GeneratePasswordShortcut(Password));
                        PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(new RC6Engine());

                        //szyfrujemy klucz prywatny haszem hasla uzytkownika
                        aes.Init(true, new KeyParameter(passShortcut)); 
                        var privateKey = Encoding.UTF8.GetBytes(rsa.ToXmlString(true)); //klucz prywatny
                        var outputBuffer = new byte[aes.GetBlockSize() + aes.GetOutputSize(privateKey.Length)];
                        

                        int outputCount = 0;
                        outputCount = aes.ProcessBytes(privateKey, 0, privateKey.Length, outputBuffer, 0);
                        fs.Write(outputBuffer, 0, outputCount);

                        outputCount = aes.DoFinal(outputBuffer, 0);
                        fs.Write(outputBuffer, 0, outputCount);
                     
                    }
                }

                MessageBox.Show("DODANO UZYTKOWNIKA!!!");
            }
            else
            {
                MessageBox.Show("LOGIN LUB HASLO PUSTE!!!");
            }
        }

        private void AddRecipientClick(object sender, RoutedEventArgs e)
        {
            var ofd = new OpenFileDialog();
            ofd.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyPictures);

            ofd.CheckFileExists = true;
            ofd.CheckPathExists = true;
            ofd.Multiselect = true;

            ofd.Filter = "Public keys | *.txt";

            if (ofd.ShowDialog() == true)
            {
                try
                {
                    foreach (var file in ofd.FileNames)
                    {
                        var recipientName = System.IO.Path.GetFileNameWithoutExtension(file);
                        RecipientsListBox.Items.Add(recipientName);
                    }
                }
                catch (Exception)
                {
                    MessageBox.Show("NIE MOZNA DODAC ODBIORCY!!!");
                }
            }
        }

        private void decryptButtonClick(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(InputFile) && (!string.IsNullOrEmpty(OutputFile)))
            {
                var selected = lbUsersAllowed.SelectedItem;
                if (selected != null)
                {
                    decryptor = new Decryptor(selected.ToString(), pbPassword.ToString());
                    decryptor.DecryptProgress += DecryptionProgress;
                    decryptor.DecryptCompleted += EncDecCompleted;
                    decryptor.bw.RunWorkerAsync();
                  
                }
                else
                {
                    MessageBox.Show("NIE WYBRANO UZYTKOWNIKA!!!");
                }
            }
            else
            {
                MessageBox.Show("NIE WYBRANO PLIKU!!!");
            }
        }

        private List<string> GetAuthorizedUsers()
        {
            try
            {
                var xml = XDocument.Parse(Decryptor.GetFileHeader());
                var users = xml.Element("EncryptedFileHeader").Element("ApprovedUsers").Descendants("User")
                            .Select(u => u.Element("Name").Value).ToList();

                if (users.Count == 0)
                    MessageBox.Show("NIE MA ODBIORCÓW!!!");
                return users;
            }
           
            catch (Exception)
            {
                MessageBox.Show("BŁĄD!!!");
                return null;
            }
        }

        private void DecryptionProgress(int value)
        {
            base.Dispatcher.Invoke((Action)delegate
                {
                    pbDecryption.Value = value;
                });
            
        }

        private void EncryptionProgress(int value)
        {
            base.Dispatcher.Invoke((Action)delegate
            {
                pbEncryption.Value = value;
            });

        }

        public void EncDecCompleted(int result, string message, bool forEncryption)
        {
            if (result == -1)
            {
                base.Dispatcher.Invoke((Action)delegate ()
                {
                    if (forEncryption)
                    {
                        pbEncryption.Value = 0;
                    }
                    else
                    {
                        pbDecryption.Value = 0;
                    }
                });

                MessageBox.Show(message);
            }
            else if (result == 1)
            {
                base.Dispatcher.Invoke((Action)delegate ()
                {
                    if (forEncryption)
                    {
                        pbEncryption.Value = 0;
                    }
                    else
                    {
                        pbDecryption.Value = 0;
                    }
                });
                MessageBox.Show(message);
            }
            else
            {
                base.Dispatcher.Invoke((Action)delegate ()
                {
                    if (forEncryption)
                    {
                        pbEncryption.Value = 100;
                    }
                    else
                    {
                        pbDecryption.Value = 100;
                    }
                });
                MessageBox.Show(message);
            }
            pbEncryption.Value = 0;
            pbDecryption.Value = 0;
        }

        private void RemoveRecipient_Click(object sender, RoutedEventArgs e)
        {
            var removeRecipient = RecipientsListBox.SelectedItem;
            if (removeRecipient != null)
            {
                RecipientsListBox.Items.Remove(removeRecipient);
            }
        }
    }
}
