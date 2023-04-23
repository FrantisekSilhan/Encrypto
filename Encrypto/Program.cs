using Encryptons;
using System.Security.Cryptography;

if (args.Length < 2)
{
    Console.WriteLine("Invalid arguments");
    return;
}

Encrypto encrypto = new Encrypto();
string command = args[0];
string keyFilePath = args[1];

switch (command.ToLower())
{
    case "encrypt":
        if (args.Length < 3)
        {
            Console.WriteLine("Invalid arguments");
            return;
        }
        string message = Encrypto.GetMessageFromArgsOrFile(args[2]);
        encrypto.LoadPublicKeyFromFile(keyFilePath);
        string encryptedMessage = Encrypto.Encrypt(message, encrypto.PublicKey);
        Console.WriteLine(encryptedMessage);
        if (args.Length > 3)
        {
            string savePath = args[3];
            File.WriteAllText(savePath, encryptedMessage);
        }
        break;

    case "decrypt":
        if (args.Length < 3)
        {
            Console.WriteLine("Invalid arguments");
            return;
        }
        string encrypted = Encrypto.GetMessageFromArgsOrFile(args[2]);
        encrypto.LoadPrivateKeyFromFile(keyFilePath);
        string decryptedMessage = Encrypto.Decrypt(encrypted, encrypto.PrivateKey);
        Console.WriteLine(decryptedMessage);
        if (args.Length > 3)
        {
            string savePath = args[3];
            File.WriteAllText(savePath, decryptedMessage);
        }
        break;

    case "sign":
        if (args.Length < 3)
        {
            Console.WriteLine("Invalid arguments");
            return;
        }
        message = Encrypto.GetMessageFromArgsOrFile(args[2]);
        encrypto.LoadPrivateKeyFromFile(keyFilePath);
        string signature = Encrypto.Sign(message, encrypto.PrivateKey);
        Console.WriteLine(signature);
        if (args.Length > 3)
        {
            string savePath = args[3];
            File.WriteAllText(savePath, signature);
        }
        break;

    case "verifysignature":
    case "verify":
        if (args.Length < 4)
        {
            Console.WriteLine("Invalid arguments");
            return;
        }
        message = Encrypto.GetMessageFromArgsOrFile(args[2]);
        encrypto.LoadPublicKeyFromFile(keyFilePath);
        string signature2 = Encrypto.GetMessageFromArgsOrFile(args[3]);
        bool isValidSignature = Encrypto.VerifySignature(message, signature2, encrypto.PublicKey);
        Console.WriteLine($"Is signature valid: {isValidSignature}");
        break;

    case "generatekeys":
    case "generate":
        if (!Directory.Exists(Path.Combine(keyFilePath, "Encrypto")))
        {
            Directory.CreateDirectory(Path.Combine(keyFilePath, "Encrypto"));
        }
        encrypto.SavePublicKeyToFile(Path.Combine(keyFilePath, "Encrypto", "rsa.pub"));
        encrypto.SavePrivateKeyToFile(Path.Combine(keyFilePath, "Encrypto", "rsa"));
        break;

    default:
        Console.WriteLine("Invalid command");
        break;
}