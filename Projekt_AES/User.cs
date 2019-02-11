using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Projekt_AES
{
    [Serializable]
    public class User
    {
        public string Login { get; set; }

        public User (string name)
        {
            Login = name;
        }

        
        public static string GeneratePasswordShortcut (string password)
        {
            StringBuilder shortcut = new StringBuilder();
            using (SHA256 sha = SHA256Managed.Create())
            {
                byte[] result = sha.ComputeHash(Encoding.UTF8.GetBytes(password));

                foreach (var tmp in result)
                    shortcut.Append(tmp.ToString("x2"));
            }

            return shortcut.ToString();
            
        }
        
        public override string ToString()
        {
            return this.Login;
        }

    }
}
