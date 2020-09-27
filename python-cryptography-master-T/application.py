import tkinter.filedialog as filedialog
import tkinter as tk
import hashlib
from decrypt import *
from encrypt import *


master = tk.Tk()
master.title('Cryptography by 3des')


def input():
    input_path_en = tk.filedialog.askopenfilename()
    input_entry.delete(1, tk.END)  # Remove current text in entry
    input_entry.insert(0, input_path_en)  # Insert the 'path'




def output():
    output_path_de = tk.filedialog.askopenfilename()
    output_entry.delete(1, tk.END)  # Remove current text in entry
    output_entry.insert(0, output_path_de)  # Insert the 'path'

        #input_path_de = tk.filedialog.askopenfilename()
        #input_entry.delete(1, tk.END)  # Remove current text in entry
        #input_entry.insert(0, input_path_de)  # Insert the 'path
       

top_frame = tk.Frame(master)
bottom_frame = tk.Frame(master)
line = tk.Frame(master, height=1, 
width=400, bg="grey80", relief='groove')

#-----------------------------------Input File----------------------------
input_path = tk.Label(bottom_frame, 
text="Input File Path Encryption:")
input_entry = tk.Entry(bottom_frame, 
text="", width=40)
browse1 = tk.Button(bottom_frame, 
text="Browse", command=input)
#----------------------------------------------------------------------


#-----------------------------------OutputFile-------------------------------
output_path = tk.Label(bottom_frame, 
text="Output File Path Decryption:")
output_entry = tk.Entry(bottom_frame, 
text="", width=40)
browse2 = tk.Button(bottom_frame, 
text="Browse", command=output)
'''
output_path = tk.Label(bottom_frame, 
text="Output File Path:")
output_entry = tk.Entry(bottom_frame, 
text="", width=40)
browse2 = tk.Button(bottom_frame, 
text="Browse", command=output)
'''
#---------------------------------------------------------------------------


def Cilck_G():
    password = pwd_entry.get()  #genKey
    password = password.encode("utf8")

    hash_pass = hashlib.sha224(password).hexdigest() #Hashing the password to 224 bits
    hash_pass = bin(int(hash_pass, 16))[2:].zfill(8)
    hash_pass = hash_pass[0:192] #truncating the hashed password to 48 hexdata (192 bits)

    fo = open("keyfile.txt","w")
    fo.write(hash_pass)	#Saving the key in a file



#Enter GenKey 
pwd_path = tk.Label(bottom_frame, text="Enter password")
pwd_entry = tk.Entry(bottom_frame, text="", width=40)
pwd_entry.insert(0, "[Enter GenKey]")
browse3 = tk.Button(bottom_frame, text="Enter", command = Cilck_G)



def Encryption_in():
    path_En = input_entry.get()
    #print (type(path_in))
    Encryption(path_En)


encrypt_button = tk.Button(bottom_frame, text='Encryption',
command = Encryption_in)


def Decryption_in():
    path_De = output_entry.get()
    Dencryption(path_De)

decrypt_button = tk.Button(bottom_frame, text='Decryption',
command = Decryption_in)


top_frame.pack(side=tk.TOP)
line.pack(pady=10)
bottom_frame.pack(side=tk.BOTTOM)

#------------------------------------------------input-----------------------
input_path.pack(pady=5)
input_entry.pack(pady=5)
browse1.pack(pady=5)
#----------------------------------------------------------------------------

#-----------------------------------------------output-----------------------
output_path.pack(pady=5)
output_entry.pack(pady=5)
browse2.pack(pady=5)
#---------------------------------------------------------------------------

#GenKey
pwd_path.pack(pady=5)
pwd_entry.pack(pady=5)
browse3.pack(pady=5)

#Entry
encrypt_button.pack(pady=20, fill=tk.X)
decrypt_button.pack(pady=20, fill=tk.X)


master.mainloop()