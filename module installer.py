import subprocess

def install_modules_from_file(filename):
    with open(filename, 'r') as file:
        module_names = file.readlines()

    for module_name in module_names:
        module_name = module_name.strip()  # Remove leading/trailing whitespace
        if module_name:  # Check for empty lines
            try:
                subprocess.check_call(['pip', 'install', module_name])
                print(f"Successfully installed {module_name}")
            except subprocess.CalledProcessError:
                print(f"Failed to install {module_name}")

if __name__ == "__main__":
    filename = "src/requirements.txt"
    install_modules_from_file(filename)
