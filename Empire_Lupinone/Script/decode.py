import base58

def decode_base58(encoded_string):
    try:
        decoded_bytes = base58.b58decode(encoded_string)
        return decoded_bytes
    except Exception as e:
        print("Error decoding Base58:", str(e))
        return None

def main(input_file, output_file):
    try:
        with open(input_file, 'r') as f:
            encoded_hash = f.read().strip()

        decoded_bytes = decode_base58(encoded_hash)

        if decoded_bytes is not None:
            with open(output_file, 'wb') as f:
                f.write(decoded_bytes)
            print("Decoded data saved to", output_file)
    except Exception as e:
        print("Error:", str(e))

if __name__ == "__main__":
    input_file = input("Name of text file: ")
    output_file = input("Enter name of output file: ")
    main(input_file, output_file)

