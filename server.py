import base64
import hashlib
import pickle
import random
import socket
import sqlite3
import threading
import time
from hashlib import sha256

import rsa
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import dh

from AsyncMessages import AsyncMessages
from tcp_by_size import recv_by_size, send_with_size
from torent_file import TorentFile

users = {}
users_keys = {}  # key = user_name , val = dp_key
async_msg = None
g, p = None, None
key = RSA.generate(3072)

# consts for sql requests
"""
db
"""
CREATE_IP_AND_PORT_TABLE_REQ = '''CREATE TABLE IPS (username varchar(20), ip varchar(16), port INTEGER)'''
CREATE_TABLE_REQ = '''CREATE TABLE files (id integer primary key, username varchar(20), file_name varchar(260) ,hash_of_file varchar(256), size INTEGER)'''
INSERT_REQ = '''INSERT INTO files (username, file_name ,hash_of_file, size) VALUES ("{user_name}", "{file_name}", "{hash}", {size})'''
DEL_REQ = '''DELETE FROM files WHERE id="{id}"'''
SELECT_BY_HASH_REQ = '''SELECT * FROM files WHERE hash_of_file ="{hash}"'''
SELECT_BY_USERNAME_REQ = '''SELECT * FROM files WHERE username ="{username}"'''
SELECT_BY_ID = '''SELECT * FROM files WHERE id ="{id}"'''
SELECT_IP_PORT_BY_USERNAME = '''SELECT ip, port FROM IPS WHERE username ="{username}"'''


def insert_torent_file(torent_file: TorentFile):
    sql_execute(INSERT_REQ.format(
        user_name=torent_file.get_user_name(),
        file_name=torent_file.get_file_name(),
        hash=torent_file.get_hash(),
        size=torent_file.get_size()))


def does_file_exist(file_hash: str, username: str) -> bool:
    sql_result_by_hash = sql_execute(SELECT_BY_HASH_REQ.format(hash=file_hash))
    sql_result_by_username = (
        sql_execute(SELECT_BY_USERNAME_REQ.format(username=username)))
    return len(sql_result_by_hash) > 0 and len(sql_result_by_username) > 0


def generate_database():  # by SQLite
    conn = sqlite3.connect('../downloads_files.db')
    c = conn.cursor()

    conn.commit()
    conn.close()
    sql_execute(CREATE_TABLE_REQ)
    sql_execute(CREATE_IP_AND_PORT_TABLE_REQ)


def sql_execute(request: str):
    # Connect to the SQLite database
    conn = sqlite3.connect('downloads_files.db')

    c = conn.cursor()
    c.execute(request)
    result = c.fetchall()
    # Commit the transaction
    conn.commit()

    # Close the connection
    conn.close()
    return result


"""
protocol
"""


def parse_UPF_message(upf_message: str) -> TorentFile:
    fields: lst[str] = upf_message.split("~")
    return TorentFile(
        fields[1],
        fields[2],
        fields[0],
        int(fields[3]))


def build_DPN_message(g: int, p: int, power_of_g_p) -> str:
    return f"DPN~{g}~{p}~{power_of_g_p}"


def create_salt():
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    chars = []
    for i in range(16):
        chars.append(random.choice(alphabet))
    return "".join(chars)


def handle_message(data):
    global async_msg
    to_send = ""
    fields = data.split("~")
    msg_type = fields[0]
    data = data[4:]
    if msg_type == "UPF":
        received_torent_file = parse_UPF_message(data)
        add_file(received_torent_file)
        to_send = "UFS~" + "your file has been successfully received"
    elif msg_type == "DLF":
        line_of_db = sql_execute(SELECT_BY_ID.format(id=fields[2]))
        hash = line_of_db[0][3]
        to_send = get_all_files_by_hash(hash)
    elif msg_type == "IFD":
        all_files = sql_execute("SELECT * FROM files")
        to_send = "SID~" + str(all_files)
    return to_send


def get_all_files_by_hash(hash:str) -> str:
    lst_files = sql_execute(SELECT_BY_HASH_REQ.format(hash=hash))
    msg_to_send = "DFS~"
    list_of_tuple_to_send = []
    for file in lst_files:
        lst_of_ip_port = sql_execute(SELECT_IP_PORT_BY_USERNAME.format(username=file[1]))
        tuple_to_send = (lst_of_ip_port[0][0], lst_of_ip_port[0][1], file[2])
        list_of_tuple_to_send.append(tuple_to_send)
    msg_to_send += str(list_of_tuple_to_send) + "~" + str(lst_files[0][4])
    return msg_to_send


def handle_client(sock, tid):
    global async_msg
    global users
    global users_keys
    global g, p
    global key

    exit_thread = False
    uname = ""
    final_key = None
    data = recv_by_size(sock).decode()
    encrypt_meth = data.split("~")[1]
    if encrypt_meth == "DP":
        while not exit_thread:
            try:
                cli_prv_num = generate_prv_num()
                to_send_g_p_res = build_DPN_message(g, p, pow(g, cli_prv_num, p))
                send_with_size(sock, to_send_g_p_res.encode())
                data = recv_by_size(sock).decode()
                client_key = int(data[4:])
                if data == "":
                    print("Client disconnected...")
                    break
                final_key = pow(client_key, cli_prv_num, p)
                final_key = _int_to_bytes(final_key)
                break
            except Exception as err:
                print(err)
                break
    else:
        public_key_pem = key.publickey().export_key()  # Get the public key in PEM format
        cipher_rsa = PKCS1_OAEP.new(key)  # Create an RSA cipher object with the server's private key
        send_with_size(sock, public_key_pem)
        encrypted_data = recv_by_size(sock)
        final_key = cipher_rsa.decrypt(encrypted_data)

    to_send = "NAP~<uname>:<pass>"

    got_name = False
    while not got_name:
        bd, iv = recv_by_size(sock).split(b"~")
        byte_data = decrypt_using_aes(final_key, bd, iv)
        data = byte_data.decode()
        if data == "":
            byte_data_to_send = to_send.encode()
            byte_encrypt_data_to_send, iv = encypt_using_aes(final_key, byte_data_to_send)
            send_with_size(sock, byte_encrypt_data_to_send + b"~" + iv)
        if data[:3] == "LOG" or data[:3] == "SUC" and len(data) > 6:
            fields = data[4:].split(":")
            uname = fields[0]
            password = fields[1]
            if uname in users.keys():
                if data[:3] == "SUC":
                    byte_data_to_send = "UNE~User Name Exists, plz choose another one".encode()
                    byte_encrypt_data_to_send, iv = encypt_using_aes(final_key, byte_data_to_send)
                    send_with_size(sock, byte_encrypt_data_to_send + b"~" + iv)
                elif data[:3] == "LOG" and password != users[uname][1]:
                    byte_data_to_send = "WRP~Wrong password, try again".encode()
                    byte_encrypt_data_to_send, iv = encypt_using_aes(final_key, byte_data_to_send)
                    send_with_size(sock, byte_encrypt_data_to_send + b"~" + iv)
                else:
                    async_msg.sock_by_user[uname] = sock
                    got_name = True
            else:
                if data[:3] == "LOG":
                    byte_data_to_send = "TSU~User Name Not Exists, did you SignUp?".encode()
                    byte_encrypt_data_to_send, iv = encypt_using_aes(final_key, byte_data_to_send)
                    send_with_size(sock, byte_encrypt_data_to_send + b"~" + iv)
                else:
                    salt = create_salt()
                    users[uname] = (uname, password, sha256((password + salt).encode()).hexdigest(), salt)
                    with open("../Users.pickle", "wb") as fn:
                        pickle.dump(users, fn)
                    async_msg.sock_by_user[uname] = sock
                    got_name = True
    sock.settimeout(0.3)

    data = "BestChat.com"
    hash_data = hashlib.sha256(data.encode()).digest()
    public_key, private_key = rsa.newkeys(2048)
    digital_signature = rsa.sign(hash_data, private_key, "SHA-256")
    send_with_size(sock, digital_signature)
    send_with_size(sock, data.encode())
    send_with_size(sock, public_key.save_pkcs1())

    users_keys[uname] = final_key

    for user in async_msg.sock_by_user.keys():
        if user != uname:
            data_to_send = f"CON~{uname}"
            encrypt_data_to_send, iv = encypt_using_aes(users_keys[user], data_to_send.encode())
            send_with_size(async_msg.sock_by_user[user], encrypt_data_to_send + b"~" + iv)
            data_to_send = f"CON~{user}"
            encrypt_data_to_send, iv = encypt_using_aes(final_key, data_to_send.encode())
            send_with_size(sock, encrypt_data_to_send + b"~" + iv)

    while not exit_thread:
        try:
            data = recv_by_size(sock)
            if data == b"":
                print("Client disconnected...")
                break
            bd, iv = data.split(b"~")
            byte_data = decrypt_using_aes(final_key, bd, iv)
            data = byte_data.decode()
            to_send = handle_message(data)
            if to_send != "":
                byte_data_to_send = to_send.encode()
                byte_encrypt_data_to_send, iv = encypt_using_aes(final_key, byte_data_to_send)
                send_with_size(sock, byte_encrypt_data_to_send + b"~" + iv)
        except socket.timeout:
            msgs = async_msg.get_async_messages_to_send(sock)
            for data in msgs:
                byte_data_to_send = data.encode()
                byte_encrypt_data_to_send, iv = encypt_using_aes(final_key, byte_data_to_send)
                send_with_size(sock, byte_encrypt_data_to_send + b"~" + iv)
                time.sleep(0.1)
            continue
        except Exception as err:
            print(err)
            break
    async_msg.delete_socket(sock)
    del async_msg.sock_by_user[uname]
    for user in async_msg.sock_by_user.keys():
        data_to_send = f"DIS~{uname}"
        encrypt_data_to_send, iv = encypt_using_aes(users_keys[user], data_to_send.encode())
        send_with_size(async_msg.sock_by_user[user], encrypt_data_to_send + b"~" + iv)
    sock.close()


def add_file(torent_file: TorentFile):
    if not does_file_exist(torent_file.get_hash(), torent_file.get_user_name()):
        insert_torent_file(torent_file)


def generate_g_p() -> (int, int):
    parameters = generate_parameters()
    g = parameters.parameter_numbers().g
    p = parameters.parameter_numbers().p
    return g, p


def get_g_p_power(g: int, p: int) -> int:
    return pow(g, generate_prv_num(), p)


def generate_prv_num():
    return random.randint(1, p - 1)


def generate_parameters():
    # Use default parameters recommended by NIST
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters


def encypt_using_aes(key, plain_text):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return base64.b64encode(cipher_text), base64.b64encode(iv)


def decrypt_using_aes(key, cipher_text, iv):
    cipher_text = base64.b64decode(cipher_text)
    iv = base64.b64decode(iv)
    decrypt_cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = unpad(decrypt_cipher.decrypt(cipher_text))
    return plain_text


def pad(data, block_size=16):
    padder = padding.PKCS7(block_size * 8).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data


def unpad(padded_data, block_size=16):
    unpadder = padding.PKCS7(block_size * 8).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data


def _int_to_bytes(n, byteorder="big"):
    # To make shorter
    n &= 0xFFFFFFFF

    # AES key sizes
    aes_key_sizes = [16, 24, 32]

    # Determine the closest AES key size
    closest_key_size = min(aes_key_sizes, key=lambda x: abs(x - n))
    return n.to_bytes(closest_key_size, byteorder)


def main():
    try:
        generate_database()
    except Exception as e:
        print(e)
    global async_msg
    global users
    global g, p
    with open("genrate_g_p.txt", 'r') as fn:
        data = fn.read()
        data = data.split('->')
        g, p = int(data[0]), int(data[1])
    try:
        with open("../Users.pickle", "rb") as fn:
            users = pickle.load(fn)
    except Exception as err:
        users = {}
    server_sock = socket.socket()
    async_msg = AsyncMessages()
    ip = '192.168.1.135'
    port = 33445
    server_sock.bind((ip, port))
    server_sock.listen(5)
    threads = []
    i = 1
    while True:
        print("Listenning....")
        cli_sock, addr = server_sock.accept()

        async_msg.add_new_socket(cli_sock)

        t = threading.Thread(target=handle_client, args=(cli_sock, i))
        t.start()
        i += 1
        threads.append(t)

        if i > 100000:
            break

    for t in threads:
        t.join()

    server_sock.close()
    print("Bye....")


if __name__ == "__main__":
    main()
