# Made by MalwareMakers 
# Github : https://github.com/MalwareMakers

import random
import string

class Encryptor_xor_hex: 
    def __init__(self,key): 
        self.key = key

    def _apply_xor(self, text):
        encrypted = ""
        key_index = 0
        for char in text:
            encrypted_char = chr(ord(char) ^ ord(self.key[key_index]))
            encrypted += encrypted_char
            key_index = (key_index + 1) % len(self.key)
        return encrypted

    def _to_hex(self, text):
        return "".join(format(ord(char), '02X') for char in text)

    def _from_hex(self, hex_text):
        return bytes.fromhex(hex_text).decode('utf-8')

    def encrypt(self, plaintext):
        encrypted = self._apply_xor(plaintext)
        return self._to_hex(encrypted)

    def decrypt(self, ciphertext):
        decrypted_hex = self._from_hex(ciphertext)
        return self._apply_xor(decrypted_hex)
    

class Github_Url:
    def __init__(self,full_url):
        self.full_url = full_url

    def convert_to_raw_url(self):
        parts = self.full_url.split('/')
        owner = parts[3]
        repo_name = parts[4]
        branch = parts[6]
        file_path = '/'.join(parts[7:])
        
        raw_url = f"https://raw.githubusercontent.com/{owner}/{repo_name}/{branch}/{file_path}"
        
        return raw_url

class Url_gen: 
    def __init__(self,url): 
        self.url = url
    
    def Gen(self): 
        git_url = Github_Url(self.url)
        raw = git_url.convert_to_raw_url()

        key_maker = Key_Gen(key_length=10)
        key = key_maker.generate_random_string()

        encode = Encryptor_xor_hex(key=key)
        encode_url = encode.encrypt(raw)

        return encode_url, key

class Key_Gen: 
    def __init__(self,key_length):
        self.key_length = key_length

    def generate_random_string(self):
        characters = string.ascii_letters
        random_string = ''.join(random.choice(characters) for _ in range(self.key_length))
        return random_string
