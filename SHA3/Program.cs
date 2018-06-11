// https://bitbucket.org/jdluzen/sha3/src/d1fd55dc225d?at=default
using System;
using System.Text;

namespace SHA3
{
    class MainClass
    {
        public static void Main(string[] args)
        {
            //length must be 224, 256, 384, or 512
            var sha3 = new SHA3Managed(512);
            var hash = sha3.ComputeHash(Encoding.UTF8.GetBytes("Hello from Steve"));
            Console.WriteLine(Convert.ToBase64String(hash));
        }
    }
}
