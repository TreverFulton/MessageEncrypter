from base64 import urlsafe_b64encode
import os
import json
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from argparse import ArgumentParser


# Function to encrypt messages using a password, and storing to a file
def encrypt(file, password, message):
    salt = os.urandom(16)                                   # Generates a random 16 byte salt for the message
    kdf = Scrypt(salt=salt,                                 # Uses previously generated salt
                 length=32,                                 # Length of derived key in bytes
                 n=2 ** 20,                                 # CPU/Memory Cost, (sensitive files should be 2**20 at ~5s)
                 r=8,                                       # Block size parameter (8 recommended)
                 p=1                                        # Parallelization Parameter (1 recommended)
                 )
    key = urlsafe_b64encode(kdf.derive(password.encode()))  # Deriving key using Scrypt and provided password
    f = Fernet(key)                                         # Initializes Fernet instance using derived key
    token = f.encrypt(message.encode())                     # Encrypts message into token using Fernet
    data = {'token': token.decode(), 'salt': salt.hex()}    # Stores token and salt into dictionary
    with open(file, 'w') as json_file:                      # Creates file at passed path
        json.dump(data, json_file, indent=4)                # Writes token/salt dictionary as JSON to the file
        json_file.close()                                   # closes file
    print("File successfully created.")                     # Outputs success statement


# Function that takes an existing file and uses password to decrypt message inside.
def decrypt(path, password):
    with open(path, 'r') as json_file:                      # Opens passed in file in read mode
        data = json.load(json_file)                         # Reads in JSON format and stores to data dictionary
        json_file.close()                                   # Closes file
    kdf = Scrypt(salt=bytes.fromhex(data['salt']),          # uses salt from the read in file
                 length=32,                                 # Length of derived key in bytes
                 n=2 ** 20,                                 # CPU/Memory Cost, (sensitive files should be 2**20 at ~5s)
                 r=8,                                       # Block size parameter (8 recommended)
                 p=1                                        # Parallelization Parameter (1 recommended)
                 )
    key = urlsafe_b64encode(kdf.derive(password.encode()))  # Deriving key using Scrypt and provided password
    f = Fernet(key)                                         # Initializes Fernet instance using derived key
    try:
        return f.decrypt(data['token'].encode()).decode()   # Attempts to decode data with provided password
    except InvalidToken:
        return ("Message failed to decrypt. "
                "Ensure provided password and "
                "file are correct.")                        # Message to display on fail


# Main function to handle command-line arguments and execute encryption or decryption
def main():
    parser = ArgumentParser(description='Writes and Reads encrypted text using a supplied key value.')

    parser.add_argument("-f", "--file",                              # Takes in filepath to encrypt to/decrypt from
                        help="Destination file for your message",
                        type=str,
                        required=True,                               # Both encrypt and decrypt require file path
                        )

    parser.add_argument("-p", "--password",                          # Takes in password to encrypt/decrypt with
                        help="Password used to encrypt message",
                        type=str,
                        required=True,                               # Both encrypt and decrypt require a password
                        )

    parser.add_argument("-m", "--message",                           # Message that will get encrypted to specified file
                        help="Message to be encrypted",
                        type=str)                                    # Message only needs to be provided for encrypting

    parser.add_argument("-o", "--overwrite",                         # Used as protection to write over existing files
                        help="Existing files will be overwritten "
                             "when this flag is used",
                        type=bool,
                        nargs='?',                                   # Can provide True/False as arg, but not required
                        const=True,                                  # If flag IS used with no arg, default to TRUE
                        default=False,                               # If flag IS NOT used, default fo FALSE
                        )

    parser.add_argument("mode",                                      # Must choose to either encrypt or decrypt
                        choices={'encrypt', 'decrypt'},              # Only these two options are allowed
                        help="Choose whether you want to "
                             "encrypt a message or decrypt an "
                             "existing message",
                        type=str,
                        )

    args = parser.parse_args()                                       # Parses command-line arguments specified above

    if args.mode == 'encrypt':                                       # Check if mode is set to encrypt
        if args.message is None:                                     # Throws error if no message is found
            parser.error("Message is required for encryption")
        if os.path.exists(args.file) and not args.overwrite:         # Check if file already exists and overwrite is off
            parser.error("File already exists. "                     # Throws error and does not encrypt over file
                         "If you wish to overwrite file use: "
                         "-o/--overwrite argument")
        encrypt(args.file, args.password, args.message)              # Calls encrypt function if no errors are found

    elif args.mode == "decrypt":                                     # Checks if mode chosen is decrypt
        if not os.path.exists(args.file):                            # Checks if file exists at target path
            parser.error(f'file {args.file} does not exist')         # Throws error if no file was found at target path
        print(decrypt(args.file, args.password))                     # Calls decrypt function if no errors are found
    else:
        print("Failed.")                                             # Catch all Failure output. Shouldn't execute ever.


if __name__ == "__main__":
    main()                                                           # Executes main function when script is run
