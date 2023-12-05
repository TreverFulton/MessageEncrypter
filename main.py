from base64 import urlsafe_b64encode
import os
import json
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from argparse import ArgumentParser


def encrypt(file, password, message):
    salt = os.urandom(16)  # Generates a random salt for the message
    kdf = Scrypt(salt=salt, length=32, n=2 ** 20, r=8, p=1)
    key = urlsafe_b64encode(kdf.derive(password.encode()))
    f = Fernet(key)
    token = f.encrypt(message.encode())
    data = {'token': token.decode(), 'salt': salt.hex()}
    with open(file, 'w+') as json_file:
        json.dump(data, json_file, indent=4)
        json_file.close()
    print("File successfully created.")


def decrypt(path, password):
    with open(path, 'r') as json_file:
        data = json.load(json_file)
        json_file.close()
    kdf = Scrypt(salt=bytes.fromhex(data['salt']), length=32, n=2 ** 20, r=8, p=1)
    key = urlsafe_b64encode(kdf.derive(password.encode()))
    f = Fernet(key)
    try:
        return f.decrypt(data['token'].encode()).decode()
    except InvalidToken:
        print("Password could not be validated.")


def main():
    parser = ArgumentParser(description='Writes and Reads encrypted text using a supplied key value.')
    parser.add_argument("-f", "--file",
                        help="Destination file for your message",
                        type=str,
                        required=True,
                        )
    parser.add_argument("-p", "--password",
                        help="Password used to encrypt message",
                        type=str,
                        required=True,
                        )
    parser.add_argument("-m", "--message",
                        help="Message to be encrypted",
                        type=str)
    parser.add_argument("-o", "--overwrite",
                        help="Existing files will be overwritten when this flag is used",
                        nargs='?',
                        const=True,
                        default=False,
                        )
    parser.add_argument("mode",
                        choices={'encrypt', 'decrypt'},
                        help="Choose whether you want to encrypt a message or decrypt an existing message",
                        type=str,
                        )

    args = parser.parse_args()

    if args.mode == 'encrypt':
        print("true")
        if args.message is None:
            parser.error("Message is required for encryption")
        if os.path.exists(args.file) and not args.overwrite:
            parser.error("File already exists. If you wish to overwrite file use -o/--overwrite argument")
        encrypt(args.file, args.password, args.message)
    elif args.mode == "decrypt":
        if not os.path.exists(args.file):
            parser.error(f'file {args.file} does not exist')
        print(decrypt(args.file, args.password))
    else:
        print("Failed.")


if __name__ == "__main__":
    main()
