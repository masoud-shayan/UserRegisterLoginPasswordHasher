using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using static System.Console;

namespace UserRegisterPasswordHashingBySalting
{
    class Program
    {
        static void Main(string[] args)
        {
            Write("Enter a new user to register: ");
            string username = ReadLine();
            Write($"Enter a password for {username}: ");
            string password = ReadLine();
            var user = Protector.Register(username, password);
            WriteLine($"Name: {user.Name}");
            WriteLine($"Salt: {user.Salt}");
            WriteLine("Password (salted and hashed): {0}", user.SaltedHashedPassword);
            WriteLine();
            bool correctPassword = false;
            while (!correctPassword)
            {
                Write("Enter a username to log in: ");
                string loginUsername = ReadLine();
                Write("Enter a password to log in: ");
                string loginPassword = ReadLine();
                correctPassword = Protector.CheckPassword(loginUsername, loginPassword);
                if (correctPassword)
                {
                    WriteLine($"Correct! {loginUsername} has been logged in.");
                }
                else
                {
                    WriteLine("Invalid username or password. Try again.");
                }
            }
        }
    }


    public class User
    {
        public string Name { get; set; }
        public string Salt { get; set; }
        public string SaltedHashedPassword { get; set; }
    }


    public class Protector
    {
        private static Dictionary<string, User> Users = new Dictionary<string, User>();


        private static string SaltAndHashPassword(string password, string salt)
        {
            var sha = SHA256.Create();
            var saltedPassword = password + salt;
            return Convert.ToBase64String(
                sha.ComputeHash(Encoding.Unicode.GetBytes(
                    saltedPassword)));
        }


        public static User Register(string username, string password)
        {
            var rng = RandomNumberGenerator.Create();
            var saltBytes = new byte[16];
            rng.GetBytes(saltBytes);
            var saltText = Convert.ToBase64String(saltBytes);


            var saltedhashedPassword = SaltAndHashPassword(password, saltText);
            var user = new User
            {
                Name = username, Salt = saltText,
                SaltedHashedPassword = saltedhashedPassword
            };
            Users.Add(user.Name, user);
            return user;
        }


        public static bool CheckPassword(string username, string password)
        {
            if (!Users.ContainsKey(username))
            {
                return false;
            }

            var user = Users[username];


            var saltedhashedPassword = SaltAndHashPassword(
                password, user.Salt);
            return (saltedhashedPassword == user.SaltedHashedPassword);
        }
    }
}