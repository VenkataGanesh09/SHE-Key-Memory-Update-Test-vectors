import customtkinter as ctk
from dataclasses import dataclass
from builtins import bytes
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from datetime import datetime


@dataclass
class KeyInfo:
    Uid_in: bytes
    KEY_NEW: bytes
    KEY_AUTH: bytes
    ID: int
    AuthID: int
    C_ID: int
    F_ID: int


@dataclass
class MessageOut:
    m1: bytes
    m2: bytes
    m3: bytes
    m4: bytes
    m5: bytes

msg_out = None

def generate_cmac(key, msg):
    cmac = CMAC.new(key, ciphermod=AES)
    cmac.update(msg)
    return cmac.digest()


def encrypt_cbc(key, value, iv=bytes([0] * 16)):
    mode = AES.MODE_CBC
    enc = AES.new(key, mode, iv=iv)
    result = enc.encrypt(value)
    return result


def array_xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_ecb(key, value):
    mode = AES.MODE_ECB
    enc = AES.new(key, mode)
    result = enc.encrypt(value)
    return result


def mp_compress(data):
    length = len(data)
    chunk_len = 16  # 128 bits chunk
    out = bytes([0] * chunk_len)
    for i in range(0, length, chunk_len):
        chunk = data[i: length + chunk_len]
        enc = encrypt_ecb(out, chunk)
        out = array_xor(array_xor(enc, chunk), out)
    return out


def mp_kdf(k, c):
    return mp_compress(k + c)


def generate_mout(user_input_key, key_update_enc_c, key_update_mac_c) -> MessageOut:
    k1 = mp_kdf(user_input_key.KEY_AUTH, key_update_enc_c)
    k2 = mp_kdf(user_input_key.KEY_AUTH, key_update_mac_c)
    k3 = mp_kdf(user_input_key.KEY_NEW, key_update_enc_c)
    k4 = mp_kdf(user_input_key.KEY_NEW, key_update_mac_c)

    m1 = user_input_key.Uid_in + ((user_input_key.ID << 4) | (user_input_key.AuthID & 0x0f)).to_bytes(1, 'big')
    m2 = encrypt_cbc(k1, ((user_input_key.C_ID << 4) | (0x0F & (user_input_key.F_ID >> 1))).to_bytes(4, 'big')
                     + ((user_input_key.F_ID << 7) & 0x80).to_bytes(1, 'big')
                     + bytes([0] * 11)
                     + user_input_key.KEY_NEW)
    m3 = generate_cmac(k2, m1 + m2)
    m4 = m1 + encrypt_ecb(k3, ((user_input_key.C_ID << 4) | 0x08).to_bytes(4, 'big') + bytes([0] * 12))
    m5 = generate_cmac(k4, m4)
    return MessageOut(m1, m2, m3, m4, m5)


def generate_basic_she(user_input_key) -> MessageOut:
    print("Reached generate_basic_she")
    return generate_mout(user_input_key, bytes.fromhex('010153484500800000000000000000B0'),
                         bytes.fromhex("010253484500800000000000000000B0"))


def generating_key_messages():
    user_input_key = KeyInfo(
        Uid_in=bytes.fromhex(uid_input.get()),
        KEY_NEW=bytes.fromhex(NewKey_input.get()),
        KEY_AUTH=bytes.fromhex(AuthKey_input.get()),
        ID=int(id_input.get()),
        AuthID=int(Authid_input.get()),
        C_ID=int(counter_input.get()),
        F_ID=int(flags_input.get())
    )
    global msg_out
    msg_out = generate_basic_she(user_input_key)
    print("m1: ", msg_out.m1.hex())
    print("m2: ", msg_out.m2.hex())
    print("m3: ", msg_out.m3.hex())
    print("m4: ", msg_out.m4.hex())
    print("m5: ", msg_out.m5.hex())

    # Convert to string
    resultm1 = ''.join(format(x, '02x') for x in msg_out.m1)
    # Update the label with the result
    displaym1.configure(text=resultm1)
    resultm2 = ''.join(format(x, '02x') for x in msg_out.m2)
    displaym2.configure(text=resultm2)
    resultm3 = ''.join(format(x, '02x') for x in msg_out.m3)
    displaym3.configure(text=resultm3)
    resultm4 = ''.join(format(x, '02x') for x in msg_out.m4)
    displaym4.configure(text=resultm4)
    resultm5 = ''.join(format(x, '02x') for x in msg_out.m5)
    displaym5.configure(text=resultm5)


    with open('SHE_Key_TestVectors.txt', 'a+') as file:
        file.write('\nKeys generated at: %s\n' % datetime.now())
        cpydata = ''.join(format(x, '02x') for x in user_input_key.Uid_in)
        file.write('Uid: %s\n' % cpydata)
        file.write('New Keyid: %s\n' % user_input_key.ID)
        cpydata = ''.join(format(x, '02x') for x in user_input_key.KEY_NEW)
        file.write('New Key: %s\n' % cpydata)
        file.write('Auth Keyid: %s\n' % user_input_key.AuthID)
        cpydata = ''.join(format(x, '02x') for x in user_input_key.KEY_AUTH)
        file.write('Auth Key: %s\n' % cpydata)
        file.write('Counter: %s\n' % user_input_key.C_ID)
        file.write('Flags: %s\n' % user_input_key.F_ID)
        file.write('M1: %s\n' %resultm1)
        file.write('M2: %s\n' % resultm2)
        file.write('M3: %s\n' % resultm3)
        file.write('M4: %s\n' % resultm4)
        file.write('M5: %s\n' % resultm5)
    file.close()

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

root = ctk.CTk()
# root.geometry("1040X960")
# root.attributes('-fullscreen', True)

width = root.winfo_screenwidth()
height = root.winfo_screenheight()
root.geometry("%dx%d" % (width * 0.4, height * 0.6))

root.title("VGanesh: SHE key memory update - Inputs generator")
frame = ctk.CTkFrame(master=root)
frame.pack(pady=20, padx=20, fill="both", expand=True)
frame.columnconfigure(0, weight=10)
frame.columnconfigure(1, weight=5)
frame.rowconfigure(18, weight=20)

label = ctk.CTkLabel(master=frame, text="Enter key Details", font=("Elephant", 24),text_color="#DC5F00")
# label.pack(pady=10, padx=20)
label.grid(row=0, column=0)

uid_input = ctk.CTkEntry(master=frame, placeholder_text="Uid_in",text_color="#80C4E9")
# uid_input.pack(pady=10, padx=80, fill="both", expand=True)
uid_input.grid(row=1, sticky='nesw')

NewKey_input = ctk.CTkEntry(master=frame, placeholder_text="New_Key_ToStore",text_color="#80C4E9")
# NewKey_input.pack(pady=10, padx=80, fill="both", expand=True)
NewKey_input.grid(row=2, sticky='nesw')

AuthKey_input = ctk.CTkEntry(master=frame, placeholder_text="Authentication_Key",text_color="#80C4E9")
# AuthKey_input.pack(pady=10, padx=80, fill="both", expand=True)
AuthKey_input.grid(row=3, sticky='nesw')

id_input = ctk.CTkEntry(master=frame, placeholder_text="New_Keyid",text_color="#80C4E9")
# id_input.pack(pady=10, padx=5)
id_input.grid(row=4, column=0)

Authid_input = ctk.CTkEntry(master=frame, placeholder_text="Authentication_Keyid",text_color="#80C4E9")
# Authid_input.pack(pady=10, padx=5)
Authid_input.grid(row=5, column=0)

counter_input = ctk.CTkEntry(master=frame, placeholder_text="NewKey_Counter",text_color="#80C4E9")
# counter_input.pack(pady=10, padx=5)
counter_input.grid(row=6, column=0)

flags_input = ctk.CTkEntry(master=frame, placeholder_text="NewKey_Flags",text_color="#80C4E9")
# flags_input.pack(pady=5, padx=2.5)
flags_input.grid(row=7, column=0)

button_gen = ctk.CTkButton(master=frame, text="Generate", fg_color="#244855",command=generating_key_messages, hover=True,
                           hover_color='#874F41')
# button.pack(pady=10, padx=10)
button_gen.grid(row=9, column=1)

displaym1 = ctk.CTkLabel(master=frame, text="Generated M1",text_color="#874F41")
displaym1.grid(row=10, sticky='nesw')
# m1display.pack(pady=10, padx=10)

# button_cpym1 = ctk.CTkButton(master=frame, text="Copy M1", command=copy_resultm1, hover=True, hover_color='#626262')
# button_cpym1.grid(row=10, column=2)

displaym2 = ctk.CTkLabel(master=frame,wraplength=300, justify="center", text="Generated M2",text_color="#874F41")
displaym2.grid(row=11, sticky='nesw')

displaym3 = ctk.CTkLabel(master=frame, text="Generated M3",text_color="#874F41")
displaym3.grid(row=12, sticky='nesw')

displaym4 = ctk.CTkLabel(master=frame,wraplength=300, justify="center", text="Generated M4",text_color="#874F41")
displaym4.grid(row=13, sticky='nesw')

displaym5 = ctk.CTkLabel(master=frame, text="Generated M5",text_color="#874F41")
displaym5.grid(row=14, sticky='nesw')


root.mainloop()
