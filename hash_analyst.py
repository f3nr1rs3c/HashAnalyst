import os
from colorama import init, Fore
from pyfiglet import Figlet
import re

# Initialize Colorama
init()

def clear_screen():
    os.system("clear")

def print_banner():
    figlet = Figlet(font='slant')  
    banner_text = figlet.renderText('Hash Analyst') 
    print(Fore.MAGENTA + banner_text + Fore.RESET)
    print(Fore.RED + "             | - | Made By : F3NR1R - Cyber Security | - |         " + Fore.RESET)

def identify_md5(hash_value):
    return re.fullmatch(r'^[a-fA-F0-9]{32}$', hash_value) is not None

def identify_sha1(hash_value):
    return re.fullmatch(r'^[a-fA-F0-9]{40}$', hash_value) is not None

def identify_sha224(hash_value):
    return re.fullmatch(r'^[a-fA-F0-9]{56}$', hash_value) is not None

def identify_sha256(hash_value):
    return re.fullmatch(r'^[a-fA-F0-9]{64}$', hash_value) is not None

def identify_sha384(hash_value):
    return re.fullmatch(r'^[a-fA-F0-9]{96}$', hash_value) is not None

def identify_sha512(hash_value):
    return re.fullmatch(r'^[a-fA-F0-9]{128}$', hash_value) is not None

def identify_sha3_224(hash_value):
    return re.fullmatch(r'^[a-fA-F0-9]{56}$', hash_value) is not None

def identify_sha3_256(hash_value):
    return re.fullmatch(r'^[a-fA-F0-9]{64}$', hash_value) is not None

def identify_sha3_384(hash_value):
    return re.fullmatch(r'^[a-fA-F0-9]{96}$', hash_value) is not None

def identify_sha3_512(hash_value):
    return re.fullmatch(r'^[a-fA-F0-9]{128}$', hash_value) is not None

def identify_blake2b(hash_value):
    return re.fullmatch(r'^[a-fA-F0-9]{128}$', hash_value) is not None

def identify_blake2s(hash_value):
    return re.fullmatch(r'^[a-fA-F0-9]{64}$', hash_value) is not None

def identify_ripemd160(hash_value):
    return re.fullmatch(r'^[a-fA-F0-9]{40}$', hash_value) is not None

def identify_hash(hash_value):
    if identify_md5(hash_value):
        return 'MD5'
    
    elif identify_sha1(hash_value):
        return 'SHA1'
    
    elif identify_sha224(hash_value):
        return 'SHA224'
    
    elif identify_sha256(hash_value):
        return 'SHA256'
    
    elif identify_sha384(hash_value):
        return 'SHA384'
    
    elif identify_sha512(hash_value):
        return 'SHA512'
    
    elif identify_sha3_224(hash_value):
        return 'SHA3-224'
    
    elif identify_sha3_256(hash_value):
        return 'SHA3-256'
    
    elif identify_sha3_384(hash_value):
        return 'SHA3-384'
    
    elif identify_sha3_512(hash_value):
        return 'SHA3-512'
    
    elif identify_blake2b(hash_value):
        return 'Blake2b'
       
    elif identify_blake2s(hash_value):
        return 'Blake2s'
       
    elif identify_ripemd160(hash_value):
        return 'RIPEMD160'
    else:
        return 'Unknown hash type'

def main():
    clear_screen()
    print_banner()
    
    # Boş bir satır ekleyerek banner ile input kısmı arasında mesafe bırakıyoruz
    print()
    
    hash_value = input(Fore.YELLOW + "Please enter the hash value: " + Fore.RESET)
    hash_type = identify_hash(hash_value)
    
    if hash_type != 'Unknown hash type':
        print(Fore.GREEN + f"Hash type: {hash_type}" + Fore.RESET)
    else:
        print("Hash type could not be determined.")

if __name__ == "__main__":
    main()
