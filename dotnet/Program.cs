using System;
using static System.Console;
using System.Text;
using System.Security.Cryptography;

namespace dotnet
{
    class Sender
    {
        static void Main(string[] args)
        {
            WriteLine("Hello World!");

            //ECDiffieHellman.Create(ECDiffieHellman.)            
            //public static System.Security.Cryptography.ECDiffieHellman Create(System.Security.Cryptography.ECCurve curve);

            ECDiffieHellmanCng alice = new ECDiffieHellmanCng();
            alice.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            alice.HashAlgorithm = CngAlgorithm.Sha256;
            ECDiffieHellmanCng bob = new ECDiffieHellmanCng();
            bob.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            bob.HashAlgorithm = CngAlgorithm.Sha256;
            byte[] bobKey = bob.DeriveKeyMaterial(alice.PublicKey);
            byte[] aliceKey = alice.DeriveKeyMaterial(bob.PublicKey);
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            aes.Key = aliceKey;


            Receiver receiver = new Receiver();
            using(ECDsaCng dsa = new  ECDsaCng())
            {
                dsa.HashAlgorithm = CngAlgorithm.Sha256;
                receiver.key = dsa.Key.Export(CngKeyBlobFormat.EccPublicBlob);
                byte[] data = new byte[] { 1, 2, 3, 4, 5, 6 };
                byte[] signature = dsa.SignData(data);
                receiver.Receive(data, signature);
                WriteLine(Environment.NewLine + "Press...");
                ReadKey();
            }
        }
    }
    class Receiver
    {
        public byte[] key;

        public void Receive(byte[] data, byte[] signature)
        {
            using (ECDsaCng ecsdKey = new ECDsaCng(CngKey.Import(key, CngKeyBlobFormat.EccPublicBlob)))
            {
                if (ecsdKey.VerifyData(data, signature))
                {
                    WriteLine("OK");
                } else
                {
                    WriteLine("BAD");
                }
            }

        }


    }
}
