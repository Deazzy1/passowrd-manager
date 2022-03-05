import os
import time
import base64
import colorama
from colorama import Fore
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

colorama.init(autoreset=True)

path = os.getcwd()
User = False
login = ''
whatdo = ''
password = []
write_file = False
save_memory = False


#open the opening screen for the Encryting program 
def opening():
   global password1
   while True: 
    os.system('cls')
    
    #ask the user what to do
    print(f'''{Fore.CYAN}What would you like to do?\n1: save a password\n2: view your passwords\n3: Save and exit the program''')

    whatdo = input(f'\n{Fore.CYAN}What would you like to do: ')
    
    # if they want to save a password
    if whatdo == '1':
      os.system('cls')
      # tell's what formate to write there password and email in
      print('put your password and your email like this | email:password')
      
      #ask for the website
      website1 = input('Website:')

      #ask for the username if the account
      name = input('Username (write null if there is no username for account):')

      # and the password
      password1 = input('Password And Email:')  

      #save's the file into one veriable 
      write1 = f"{website1}: {name}:{password1}"
      print(write1)
      login = input('Master Password:')   
      
      #dencryte's the file to write
      DNFILE(login,'Pass.ME',True)
      
      #writes the new info
      with open('Pass', 'a') as f:
          f.write(write1)
          f.close()
      
      #then it incrytes the file with the new info
      ENFILE(login, 'Pass')
      os.system('cls')
      
      #tells the user there done
      print(f"{Fore.GREEN}Your password has been encryted, it has been saved into the Pass.ME file.")
      os.remove('Pass')
      time.sleep(2.5)

    if whatdo == '2':
      os.system('cls')

      #asks the user password
      login = input('Master Password:')

      #dencrytes the file for reading
      DNFILE(login, "Pass.ME", False)
      #prints it
      print(str(password1))
      
      #and asks when there done, press enter
      input('Press enter when you are done:')   
      os.system('cls')  

    if whatdo == '3':
      os.system('cls')
      #exites the program
      print(f"{Fore.GREEN}See you next time!")
      time.sleep(2)
      break

#EN file
def ENFILE(masterpassword, file_path):
    password_provided = masterpassword
    password = password_provided.encode()  # Convert to type bytes
    salt = b'salt_'  # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once
    with open(file_path, 'rb') as f:
        data = f.read()  # Read the bytes of the input file

    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)

    with open(f'{file_path}.ME', 'wb') as f:
        f.write(encrypted)  # Write the encrypted bytes to the output file
    


#DN file
def DNFILE(masterpassword, file_path1, write_file):
    global password1
    password_provided = masterpassword
    password = password_provided.encode()  # Convert to type bytes

    salt = b'salt_'  # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once
    time.sleep(1.5)
    with open(file_path1, 'rb') as f:
        data = f.read()  # Read the bytes of the encrypted file

        
    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(data)
        password1 = decrypted

        if write_file == True: # if the write_file is enabled
            with open('Pass', 'a') as f:
                f.write(str(decrypted))  

    except InvalidToken as e: # if the password is invalid
        os.system('cls')
        print(f"{Fore.RED}Invalid Key - Unsuccessfully decrypted")
        time.sleep(2.5)
        exit(0)

# settings up for new users
def Setting_Up():  
  try:
    #there is already a account  
    with open(r'Pass.ME') as f:
      User = True
  #else    
  except:
      User = False

  if User == False:
    #welcomeing the user  
    print(f'''{Fore.CYAN}
Welcome new user! To start using Molly Mannger. Please make a master password, 
make sure that you remember this password!
''')
    
    #ask's the user for a password
    login = input('Master Password:') 
    os.system('cls')

    #set's up the file where the passwords will be saved 
    with open(f'Pass', 'w') as INFO:
        pass 
    #encrytes the file
    ENFILE(login, 'Pass')
    os.remove('Pass')
    
    #tells the user setup is done
    print(f'{Fore.GREEN}You are all setup! Have fun using Molly Mannger.')
    time.sleep(3.5)
    os.system('cls')


#loging in
def login():

  #ask the user for there password  
  print(f'{Fore.CYAN}Login Using your master password!')
  login = input('Master Password:')
  
  # trys the password to unincryte the password file
  DNFILE(login, 'Pass.ME', False) 
  os.system('cls')

  # if there was no error's, it continue's
  print(f'{Fore.GREEN} Login success!')   
  time.sleep(1)

# clear the terminal
os.system('cls')

Setting_Up()
login()
opening()