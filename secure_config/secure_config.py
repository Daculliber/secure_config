import pickle, hashlib, random
import os
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode
from system_fingerprinter import machine_fingerprint, encode_date ,compare_date_from_file

class secure_config:
    def __init__(self):
        self.auth_key_hash=None
        self.time_stamp=None
        self.system_fingerprint=None
        self.status="inactive"  #inactive, active, disabled, corrupted
        self.security_settings="TF"  #timestamp: T corrupt / t disable; system fingerprint: F corrupt / f disable; pass: p (if args not present, ignore warnings)
        self.content=None
        self.print_data=None
        self._fernet_salt=None # Initialize _fernet_salt here

    def _derive_fernet_key(self, password: str) -> bytes:
        """Derives a Fernet key from the password and the stored salt."""
        if not self._fernet_salt:
            raise ValueError("Fernet salt not set. File might be corrupted or not properly generated.")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # Fernet keys are 32 bytes
            salt=self._fernet_salt,
            iterations=480000, # Recommended number of iterations (adjust as needed for performance vs. security)
            backend=default_backend()
        )
        key = urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
        return key


    def generate_auth_key(self,length):
        key=""
        chars="ABCDEFGHIJKLMNOPQRSTUVXWXYZ1234567890"
        for i in range(length):
            for a in range(5):
                key+=random.choice(chars)
            if i < length-1:
                key+="-"
        return key

    #encr
    def _hash(self,inp: str):
        return str(hashlib.sha256(inp.encode("utf-8")).hexdigest())

    def encrypt(self,pas):
        """Encrypts sensitive attributes using Fernet."""
        try:
            fernet_key = self._derive_fernet_key(pas)
            f = Fernet(fernet_key)

            # Convert string attributes to bytes before encryption
            # Ensure attributes are not None before encoding, or handle None gracefully
            self.auth_key_hash = f.encrypt(self.auth_key_hash.encode('utf-8')) if self.auth_key_hash is not None else None
            self.status = f.encrypt(self.status.encode('utf-8'))
            self.time_stamp = f.encrypt(self.time_stamp.encode('utf-8')) if self.time_stamp is not None else None
            self.system_fingerprint = f.encrypt(self.system_fingerprint.encode('utf-8')) if self.system_fingerprint is not None else None
            
            # Pickle content to bytes, then encrypt
            if self.content is not None:
                self.content = f.encrypt(pickle.dumps(self.content))

        except (ValueError, InvalidToken) as e:
            # If key derivation fails or Fernet instance creation fails, likely a salt issue or bad password handling
            if self.print_data==True:
                print(f"Encryption error: {e}")
            self.status = "corrupted"
            self.content = None # Ensure content is wiped on encryption failure
        except Exception as e:
            if self.print_data==True:
                print(f"An unexpected error occurred during encryption: {e}")
            self.status = "corrupted"
            self.content = None

    def decrypt(self,pas):
        """Decrypts sensitive attributes using Fernet."""
        try:
            fernet_key = self._derive_fernet_key(pas)
            f = Fernet(fernet_key)

            # Decrypt byte attributes and decode to strings
            self.auth_key_hash = f.decrypt(self.auth_key_hash).decode('utf-8') if self.auth_key_hash is not None else None
            self.status = f.decrypt(self.status).decode('utf-8')
            self.time_stamp = f.decrypt(self.time_stamp).decode('utf-8') if self.time_stamp is not None else None
            self.system_fingerprint = f.decrypt(self.system_fingerprint).decode('utf-8') if self.system_fingerprint is not None else None

            # Decrypt content bytes, then unpickle
            if self.content is not None:
                self.content = pickle.loads(f.decrypt(self.content))

        except InvalidToken:
            if self.print_data:
                print("Decryption failed: Incorrect password or corrupted data.")
            self.status = "corrupted"
            self.auth_key_hash = None
            self.time_stamp = None
            self.system_fingerprint = None
            self.content = None # Wipe content on decryption failure
            self.encrypt(pas) # Use the same (incorrect, but consistent for saving) password to encrypt new state
        except Exception as e:
            if self.print_data:
                print(f"An unexpected error occurred during decryption: {e}")
            self.status = "corrupted"
            self.auth_key_hash = None
            self.time_stamp = None
            self.system_fingerprint = None
            self.content = None
            self.encrypt(pas) # Attempt to encrypt the corrupted state

    #file
    def kill_file(self,err): #err ="f/t" f=fingerprint t= timestamp
        args=[]
        ret=False
        for i in self.security_settings:
            args.append(i)
        if not self.status=="corrupted":
            if err=="f":
                if "F" in args:
                    self.status="corrupted"
                    self.content=None
                elif "f" in args:
                    self.status="disabled"
                elif "p" in args:
                    ret=True
            if err=="t":
                if "T" in args:
                    self.status="corrupted"
                    self.content=None
                elif "t" in args:
                    self.status="disabled"
                elif "p" in args:
                    ret=True
        #print("status" ,self.status)
        return ret
        
    def save(self,path):
        """Saves the secure_config object to a file."""
        with open(path,"wb") as f:
            pickle.dump(self,f)

    def load(self,path):
        """Loads the secure_config object from a file."""
        with open(path,"rb") as f:
            data=pickle.load(f)
        self.auth_key_hash=data.auth_key_hash
        self.time_stamp=data.time_stamp
        self.system_fingerprint=data.system_fingerprint
        self.status=data.status
        self.security_settings=data.security_settings
        self.content=data.content
        self.print_data=data.print_data
        self._fernet_salt=data._fernet_salt # Load the salt

    def generate(self,path,key_length=None, password="", args = None, print_data=True, key=None): # args timestamp T corrupt / t disable; system fingerprint F corrupt / f disable; p pass error if arg missing
        if key==None:
            if key_length==None:
                key_length=4
            auth_key=self.generate_auth_key(key_length)
        else:
            auth_key=key
        self.auth_key_hash=self._hash(auth_key)
        self.print_data=print_data
        self.status="inactive" # Initial status
        self.time_stamp="none" # Initial timestamp placeholder
        self.system_fingerprint="none" # Initial fingerprint placeholder

        self._fernet_salt = os.urandom(16) # Generate a new 16-byte salt
        
        self.encrypt(password) #encoded
        if not args == None:
            self.security_settings=args
        self.save(path)
        print("The secure file was generated")
        print("Activation key: ",auth_key)
        return auth_key

    def activate(self,path,password,auth_key): 
        self.load(path) #loads file
        self.decrypt(password)
        print_data=self.print_data
        if self.status=="corrupted":
            if print_data==True:
                print("Activation failed: File corrupted")
            return False
        if self.auth_key_hash==self._hash(auth_key): #verifies key
            self.time_stamp=encode_date()
            self.status="active" #activates file
            self.system_fingerprint=machine_fingerprint()
            self.encrypt(password)
            self.save(path) # Changed to save without content argument
            if print_data==True:
                print("The file was acctivated successfully.")
            return True
        else:
            if print_data==True:
                print("Activation failed")
            self.encrypt(password) # Re-encrypt current state (inactive/disabled/corrupted from decrypt)
            self.save(path) # Changed to save without content argument
            return False

    def read_file(self,path,password):
        self.load(path)# loads file
        self.decrypt(password)
        print_data=self.print_data
        Pass = False
        if self.status =="corrupted":
            if print_data==True:
                print("The file was irreversibly corrupted")
            self.encrypt(password)
            self.save(path)
            return False
        if self.status=="disabled":
            if print_data==True:
                print("The file is disabled. Please reactivate.")
            self.encrypt(password)
            self.save(path) # Changed to save without content argument
            return False
        if self.status =="inactive":
            if print_data==True:
                print("The file is inactive. Please Activate")
            return False
        if self.system_fingerprint==machine_fingerprint() and self.status=="active": #checks system fingerprint
            if compare_date_from_file(time_from_file=self.time_stamp,path=path,seconds=10) == True: #checks timestamp
                return self.content
            else:
                if print_data==True:
                    print("The file timestamp is inavalid")
                Pass=self.kill_file("t")
                if Pass == True:
                    return self.content
                else:
                    self.encrypt(password)
                    self.save(path) # Changed to save without content argument
                    return False
        else:
            if print_data==True:
                print("System fingerprint is invalid")
            Pass=self.kill_file("f")
            if Pass ==True:
                return self.content
            else:
                self.encrypt(password)
                self.save(path) # Changed to save without content argument
                return False

    def check_status(self,path,password):
        self.load(path)
        self.decrypt(password)
        return self.status

    def write_file(self,path,password,content):
        # read_file performs load and decrypt, and all checks
        if self.read_file(path,password) is not False:
            self.time_stamp=encode_date() #encode timestamp into file (plaintext)
            self.content = content # Set new content to be encrypted
            self.encrypt(password) # Encrypt all attributes including the new content
            self.save(path) # Save the now encrypted object.
            return True # Indicate successful write
        else:
            self.load(path) # Reload to ensure current state is accurate after failed read_file
            print_data=self.print_data
            if print_data==True:
                print("Cannot write file.")
            return False

#Test:

#sc=secure_config()
#sc.generate("testfile",password="m47hh4yy4by",args="ft",print_data=False,key="X63XX-SB37X-7JJF8-KHRIQ")
#sc.activate("testfile","m47hh4yy4by","X63XX-SB37X-7JJF8-KHRIQ")
#cont="Hello world!"
#sc.write_file("testfile","m47hh4yy4by",cont)
#print(sc.read_file("testfile","m47hh4yy4by"))
#print(sc.check_status("testfile","m47hh4yy4by"))

#Usage:

#generate -- generates the secure file and activation key to be delivered with the program (This is not part of the program itself, but rather a tool to make the file to be delivered with the program)
#generate(path,key_length, password <to be embeded in the program>,args<# args timestamp T corrupt / t disable; system fingerprint F corrupt / f disable; p pass errors if arg missing>,
#       print_data=True<Hides the library's printing useful if you use it in a program>, key<predefined key(optional)>)
#activate(path,password,auth_key) if file inactive or disabled
#read_file(path,password) returns the content of the file(ie. what YOU store inside it)
#write_file(path,password,content) allows you to write [content: anything] to the file just like pickle
#def check_status(path,password) returns the status of the file as str: "inactive","disabled","active",or "corrupted".