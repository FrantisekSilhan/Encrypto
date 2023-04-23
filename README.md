
# Encrypto.exe

  

Encrypto.exe is a command-line tool that provides functionality for encrypting, decrypting, signing, and verifying digital signatures using RSA encryption.

  

## Usage:

  

The following commands can be used with Encrypto.exe:

  

### GenerateKeys|Generate:

  

>Encrypto.exe GenerateKeys|Generate <key_file_path>

Generates a new RSA key pair and saves it to the specified key file path.

  
  

### Encrypt:

>Encrypto.exe Encrypt <public_key_path>  <message|message_file_path> [<output_file_path>]

Encrypts the message or message file using the specified public key and outputs the encrypted message, or saves the encrypted message to the specified output file path.

  
  

### Decrypt:

>Encrypto.exe Decrypt <private_key_path>  <encrypted_message|encrypted_message_file_path [<output_file_path>]

Decrypts the encrypted message or message file using the specified private key and outputs the decrypted message, or saves the decrypted message to the specified output file path.

  
  

### Sign:

>Encrypto.exe Sign <private_key_path>  <message|message_file_path> [<output_file_path>]

Creates a digital signature of the message or message file using the specified private key and outputs the signature, or saves the signature to the specified output file path.

  
  

### VerifySignature|Verify:

>Encrypto.exe VerifySignature|Verify <public_key_path>  <message|message_file_path>  <signature|signature_file_path>

Verifies the digital signature of the message or message file using the specified public key and signature, or using the specified public key and signature file.

  

## Example:

>Encrypto.exe Generate ./

>Encrypto.exe Encrypt ./Encrypto/rsa.pub ./Files/message.txt ./Files/encrypted.txt
>Encrypto.exe Encrypt ./Encrypto/rsa.pub "Hello, world!" ./Files/encrypted.txt

>Encrypto.exe Decrypt ./Encrypto/rsa ./Files/encrypted.txt ./Files/decrypted.txt
>Encrypto.exe Decrypt ./Encrypto/rsa "Hello, world!" ./Files/decrypted.txt

>Encrypto.exe Sign ./Encrypto/rsa ./Files/message.txt ./Files/signature.txt
>Encrypto.exe Sign ./Encrypto/rsa "Hello, world!" ./Files/signature.txt

>Encrypto.exe Verify ./Encrypto/rsa.pub ./Files/message.txt ./Files/signature.txt
>Encrypto.exe Verify ./Encrypto/rsa.pub "Hello world!" "BCAD0BF149..."

  
  

#### Encrypto.exe Generate ./

Generates a new RSA key pair and saves it to Encrypto directory in the current directory as rsa.pub (public key) and rsa (private key) files. The keys can then be used for encryption, decryption, signing, and verifying signatures.

  

#### Encrypto.exe Encrypt ./Encrypto/rsa.pub ./Files/message.txt ./Files/encrypted.txt

Encrypts the contents of message.txt using the public key located at ./Encrypto/rsa.pub and saves the encrypted message to ./Files/encrypted.txt. The encrypted message can be transmitted securely and can only be decrypted using the corresponding private key.

  

#### Encrypto.exe Decrypt ./Encrypto/rsa ./Files/encrypted.txt ./Files/decrypted.txt

Decrypts the encrypted message stored in ./Files/encrypted.txt using the private key located at ./Encrypto/rsa and saves the decrypted message to ./Files/decrypted.txt. Only the holder of the corresponding private key can decrypt the message and read its contents.

  

#### Encrypto.exe Sign ./Encrypto/rsa ./Files/message.txt ./Files/signature.txt

Creates a digital signature of the contents of message.txt using the private key located at ./Encrypto/rsa and saves the signature to ./Files/signature.txt. The signature can be used to verify the authenticity and integrity of the message and to ensure that it has not been tampered with.

  

#### Encrypto.exe Verify ./Encrypto/rsa.pub ./Files/message.txt ./Files/signature.txt

Verifies the digital signature of the contents of message.txt using the public key located at ./Encrypto/rsa.pub and the signature located at ./Files/signature.txt. If the verification is successful, it means that the message has not been tampered with and that it was indeed signed by the holder of the corresponding private key.
