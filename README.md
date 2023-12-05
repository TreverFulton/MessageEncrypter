
# MessageEncrypter
#### Final Project for Python for Networking(COMP-10247)
This Python script provides a simple command-line interface for encrypting and decrypting messages using the Fernet encryption scheme from the cryptography library. It produces a json file that contains an encrypted token and its associated salt. 

The salt, along with a user provided password, will allow for easy encryption and decryption of that token, which will contain a user generated message.

## Installation
Make sure you have [Python](https://www.python.org/downloads/) installed. Clone this repo and install the cryptography module using:

```bash
pip install cryptography
```

## Encrypting a Message
To encrypt a message and save it to a file, use:

```bash
python MessageEncrypter.py encrypt -f <file_path> -p <password> -m <message_to_encrypt>
```
* -f, --file: Destination file for your encrypted message.
* -p, --password: Password used to encrypt the message.
* -m, --message: Message to be encrypted.
#### Additional options:

* -o, --overwrite: Use this flag to overwrite an existing file. (Optional)

## Decrypting a Message
To decrypt a message from a file, use:

```bash
python MessageEncrypter.py decrypt -f <file_path> -p <password>
```
* -f, --file: File path to the encrypted message.
*  -p, --password: Password used to decrypt the message.

## Examples
#### Encrypting a message:
```bash
python MessageEncrypter.py encrypt -f secret.txt -p mypassword -m "This is a secret message."
```
#### Decrypting a message:
```bash
python MessageEncrypter.py decrypt -f secret.txt -p mypassword
```
## Notes
* For decryption, ensure you provide the correct password used during encryption.
* Use the -o/--overwrite flag to overwrite existing files when encrypting messages.
* Files generated from the encrypt() function are stored in a .json format

## Contributing
Feel free to open issues or pull requests for any improvements or bug fixes.

## Acknowledgements

 - [Fernet Symmetric Encryption](https://cryptography.io/en/latest/fernet/)
 - [Arg Parse](https://docs.python.org/3/library/argparse.html)
 - [README.md: The Ultimate Guide](https://tiloid.com/p/readme-md-the-ultimate-guide)


## License

[MIT](https://choosealicense.com/licenses/mit/)


## Feedback

If you have any feedback, please reach out to me at trever.fulton@mohawkcollege.ca

