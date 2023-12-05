import base64
import os
import json

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from argparse import ArgumentParser


def encrypt(file, password, message):
    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2 ** 20, r=8, p=1)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    f = Fernet(key)
    token = f.encrypt(message.encode())
    data = {'token': token.decode(), 'salt': salt.hex()}
    with open(file, 'w') as json_file:
        json.dump(data, json_file, indent=4)
        json_file.close()


def decrypt(path, password):
    with open(path, 'r') as json_file:
        data = json.load(json_file)
        json_file.close()
        print(data['salt'])
    kdf = Scrypt(salt=bytes.fromhex(data['salt']), length=32, n=2 ** 20, r=8, p=1)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    f = Fernet(key)
    print(f.decrypt(data['token'].encode()).decode())


def main():
    parser = ArgumentParser(description='Writes and Reads encrypted text using a supplied key value.')
    parser.add_argument("-f", "--file",
                        help="destination FILE for your message",
                        type=str,
                        required=True,
                        )
    parser.add_argument("-p", "--password",
                        help="password used to encrypt message",
                        type=str,
                        required=True,
                        )
    parser.add_argument("-m", "--message",
                        help="message to be encrypted",
                        type=str)
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
        # elif os.path.exists(args.file):
        #    parser.error("Cannot write to existing message file, exiting program")
        else:
            encrypt(args.file, args.password, args.message)
    elif args.mode == "decrypt":
        decrypt(args.file, args.password)
    else:
        print("failed")


if __name__ == "__main__":
    main()
