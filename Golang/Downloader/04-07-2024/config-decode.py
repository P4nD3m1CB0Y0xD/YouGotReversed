import base64


def b64decode_xor(data: str, key: bytes) -> bytearray:
    try:
        cipher_text = base64.b64decode(data)
    except Exception as e:
        return None
    
    bKey = bytes(key)
    cipher_text = bytearray(cipher_text)
    for i in range(len(cipher_text)):
        cipher_text[i] ^= bKey[i % len(bKey)]

    return cipher_text.decode()

def main() -> None:
    encoded_data: list[str] = ["GAcQAR9KXEsGGwddBx4BFQEHGAMZFwEQABkJBRUDXhALHEMHHBYVQgoaFA==", "M0k4IR4fFBYQAVA1DR0JAy8wHhwRCUQ+KjQvMxAeAxIT", 
                               "GAcQAR9KXEsSAx0WFhIFHwEBBwMcBgcQA14QCxxDHhwSEEMTEgkUHhFdFBkcTwEICVE=", "IxwCBRsRAQEtIRkQFh4fHxUQLTsZHQAeGwMvJwQeAhYKBToVARcYAx4vNgQC"]
    xor_key: bytes  = b"psdql"

    for data in encoded_data:
        print(b64decode_xor(data, xor_key))


if __name__ == '__main__':
    main()
