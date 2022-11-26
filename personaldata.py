from tkinter import *
from tkinter import filedialog as fd
import hashlib
from simplecrypt import encrypt, decrypt

root = Tk()
root.geometry("800x600")
root.title("Encrypting Personal Data")
root.config(background="#DBDBDB")

file_name_entry = ""
encryption_text_data = ""

def startEncryption():
    headingLabel = Label(root, text="Encrypting Personal Data", fg="black", bg="#DBDBDB", font=("Comic Sans MS", "24", "bold"))
    headingLabel.place(relx=0.5, rely=0.05, anchor=CENTER)
    
    
    
    startENCbtn = Button(root, text="Start Encryption", bg="#B0B5B3", fg="black", command = StartEncryption)
    startENCbtn.place(relx=0.3, rely=0.5, anchor=CENTER)
    
    startDECbtn = Button(root, text="Start Decryption" , bg="#B0B5B3", fg="black", command = StartDecryption)
    startDECbtn.place(relx=0.7, rely=0.5, anchor=CENTER)
    
    

def saveData():
    global file_name_entry, encryption_text_data
    file_name = file_name_entry.get()
    file = open(file_name + ".txt", 'w')
    data = encryption_text_data.get(0, END)
    ciphercode = encrypt("ZED", data)
    theHex = ciphercode.hex()
    print(theHex)
    write(theHex)
    """entry element""".delete(0, END)
    """text element""".delete(0, END)
    root.messsagebox.showinfo(title="Successful", message="Data successfully encrypted and update!")
    createBtn = Button(root, text="Create", bg="#B0B5B3", fg="black", command = saveData, font=("Comic Sans MS", "15", "bold"))
    createBtn.place(relx)
    
decrypting_text_data = ""    
    
def viewData():
    global decrypting_text_data
    text_file = filedialog.askopenfilename(title="Opening File", filetypes =(("Text Files", "*.txt"),))
    name = os.path.basename(text_file)
    print(name)
    text_file2 = open(name, 'r')
    paragraph = read(text_file2)
    bytes = bytes.fromhex(paragraph)
    decrypted = decrypt("ZED", bytes)
    finalData = decode(decrypted)
    insert(END, finalData)
    
    

    