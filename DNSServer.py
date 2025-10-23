import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
import dns.rrset             # <<-- added
import socket
import threading
import signal
import os
import sys
...
salt = b'Tandon'
password = os.environ.get("NYU_EMAIL", "student_placeholder@nyu.edu")
input_string = "AlwaysWatching"

encrypted_value = encrypt_with_aes(input_string, password, salt) # exfil function

try:
    decrypted_value = decrypt_with_aes(encrypted_value, password, salt)  # exfil function
except Exception as e:
    decrypted_value = None
    print("Warning: decrypt failed at startup (this is OK for exfil). Error:", e)
