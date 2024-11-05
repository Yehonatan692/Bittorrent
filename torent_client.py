import tkinter as tk
from tkinter import ttk
import wx, os
import socket
import threading
import datetime
from tcp_by_size import recv_by_size, send_with_size
from sys import argv
import random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import padding
from Crypto.Random import get_random_bytes
from server_for_downloading.client_for_downloading import end_to_end_download_file
import base64
import rsa
import hashlib
from hashlib import sha256

"""
WXpython
"""

APP_SIZE_X = 500
APP_SIZE_Y = 600


class WxChatClient(wx.Dialog):

    def __init__(self, parent, id, title, ip):
        wx.Dialog.__init__(self, parent, id, title, size=(APP_SIZE_X, APP_SIZE_Y))
        self.ip = ip
        self.state = "start"
        self.all_users = []
        self.to_user = ""
        self.uname = ""
        self.encrypt_dp = False
        self.encrypt_rsa = False
        self.cipher_rsa = None

        self.p = None
        self.g = None
        self.prv_num = None
        self.final_key = None

        self.BtnClos = wx.Button(self, 2, "Close Connection", (190, 280))
        self.BtnLogin = wx.Button(self, 3, "Login", (300, 200), (100, -1))
        self.BtnSend = wx.Button(self, 4, "Publish File", (200, 75), (100, -1))
        self.BtnSignUp = wx.Button(self, 5, "SignUp", (100, 200), (100, -1))
        self.DataToSendLabel = wx.StaticText(self, label="Enter Path:", pos=(0, 55))
        self.data_to_server = wx.TextCtrl(self, value="", pos=(60, 50), size=(320, -1))
        self.DataFromServerLabel = wx.StaticText(self, label="Data From Server:", pos=(10, 350))
        self.data_from_server = wx.ListBox(self, pos=(10, 370), size=(460, 180), style=wx.LB_SINGLE)

        self.ChooseLabel = wx.StaticText(self, label="Choose Encryption", pos=(200, 20))
        self.BtnDP = wx.Button(self, 6, "DP Hellman", (100, 50), (300, 200))
        self.BtnRSA = wx.Button(self, 7, "RSA", (100, 330), (300, 200))

        self.MSGLabel = wx.StaticText(self, label="Message Board:", pos=(0, 485))
        self.msg = wx.ListBox(self, pos=(0, 500), size=(500, 200), style=wx.LB_SINGLE)

        self.UserName = wx.StaticText(self, label="", pos=(60, 5))
        self.UserName.Hide()
        self.EnterUsernameLabel = wx.StaticText(self, label="UserName:", pos=(100, 50))
        self.EnterUsername = wx.TextCtrl(self, value="", pos=(100, 70), size=(300, -1))
        self.EnterPasswordLabel = wx.StaticText(self, label="Password:", pos=(100, 100))
        self.EnterPassword = wx.TextCtrl(self, value="", pos=(100, 120), size=(300, -1))

        self.list_of_files_lable = wx.StaticText(self, label="FILES TO DOWNLOAD:", pos=(10, 98))
        self.search_bar = wx.SearchCtrl(self, -1, pos=(10, 40), size=(200, -1), style=wx.TE_PROCESS_ENTER)
        self.searchBtn = wx.Button(self, 10, "Press for Downloading", (280, 40), (200, -1))
        self.list_of_files = wx.ListBox(self, pos=(10, 115), size=(460, 150), style=wx.LB_SINGLE)

        self.UploadFile = wx.Button(self, 8, "UPLOAD PAGE", (40, 60), (200, 200))
        self.DownloadFile = wx.Button(self, 9, "DOWNLOAD PAGE", (250, 60), (200, 200))
        self.Bind(wx.EVT_LISTBOX, self.entered_file_for_downloading, self.list_of_files)



        self.listener = None
        self.cli_sock = None

        self.Bind(wx.EVT_BUTTON, self.CloseConnection, id=2)
        self.Bind(wx.EVT_BUTTON, self.OnTcpConnectLogin, id=3)
        self.Bind(wx.EVT_BUTTON, self.OnTcpSend, id=4)
        self.Bind(wx.EVT_BUTTON, self.OnTcpConnectSignUp, id=5)
        self.Bind(wx.EVT_BUTTON, self.choose_encryption_dp, id=6)
        self.Bind(wx.EVT_BUTTON, self.choose_encryption_rsa, id=7)
        self.Bind(wx.EVT_BUTTON, self.upload_page, id=8)
        self.Bind(wx.EVT_BUTTON, self.download_page, id=9)
        self.Bind(wx.EVT_BUTTON, self.onSearch, id=10)

        self.before_encrypt_choose()

        self.Centre()
        self.ShowModal()

    def onSearch(self, evt):
        search_query = self.search_bar.GetValue().lower()
        all_items = self.list_of_files.GetStrings()
        filtered_items = [item for item in all_items if search_query in item.lower()]
        self.list_of_files.Set(filtered_items)

    def initialization_files_for_downloading(self):
        to_send = "IFD~"
        encrypt_data_to_send, iv = self.encypt_using_aes(self.final_key, to_send.encode())
        send_with_size(self.cli_sock, encrypt_data_to_send + b"~" + iv)

    def entered_file_for_downloading(self, evt):
        self.files = self.list_of_files.GetString(self.list_of_files.GetSelection())
        fields = self.files.split('->')
        id = fields[2]
        id = id[13:]
        to_send = "DLF~" + self.uname + "~" + id
        encrypt_data_to_send, iv = self.encypt_using_aes(self.final_key, to_send.encode())
        send_with_size(self.cli_sock, encrypt_data_to_send + b"~" + iv)

    def CloseConnection(self, event):
        self.cli_sock.close()
        self.data_from_server.Append("Connection Closed")
        self.Destroy()

    def generate_prv_num(self):
        return random.randint(1, self.p - 1)

    def dp_exchange(self):
        data = recv_by_size(self.cli_sock).decode()
        action = data[:3]
        data = data[4:]
        fields = data.split("~")
        self.g = int(fields[0])
        self.p = int(fields[1])
        self.prv_num = self.generate_prv_num()
        serv_res = int(fields[2])   
        res = "DPR~" + str(pow(self.g, self.prv_num, self.p))
        send_with_size(self.cli_sock, res.encode())
        self.final_key = pow(serv_res, self.prv_num, self.p)
        self.final_key = self._int_to_bytes(self.final_key)

    def rsa_exchange(self):
        serialized_key = recv_by_size(self.cli_sock)
        public_key = RSA.importKey(serialized_key)
        self.cipher_rsa = PKCS1_OAEP.new(public_key)
        self.final_key = get_random_bytes(16)
        cipher_text = self.cipher_rsa.encrypt(self.final_key)
        send_with_size(self.cli_sock, cipher_text)

    def choose_encryption_dp(self, event):
        self.encrypt_dp = True
        self.after_encrypt_choose()

    def choose_encryption_rsa(self, event):
        self.encrypt_rsa = True
        self.after_encrypt_choose()

    def pad(self, data, block_size=16):
        padder = padding.PKCS7(block_size * 8).padder()
        padded_data = padder.update(data) + padder.finalize()
        return padded_data

    def unpad(self, padded_data, block_size=16):
        unpadder = padding.PKCS7(block_size * 8).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data

    def encypt_using_aes(self, key, plain_text):
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
        cipher_text = cipher.encrypt(self.pad(plain_text, AES.block_size))
        return base64.b64encode(cipher_text), base64.b64encode(iv)

    def decrypt_using_aes(self, key, cipher_text, iv):
        cipher_text = base64.b64decode(cipher_text)
        iv = base64.b64decode(iv)
        decrypt_cipher = AES.new(key, AES.MODE_CBC, iv)
        plain_text = self.unpad(decrypt_cipher.decrypt(cipher_text))
        return plain_text

    def after_login_or_signup(self):
        self.UserName.Hide()
        self.EnterUsernameLabel.Hide()
        self.EnterUsernameLabel.Move(0, 0)
        self.EnterUsernameLabel.Show()
        self.EnterPassword.Hide()
        self.EnterPasswordLabel.Hide()
        self.BtnLogin.Hide()
        self.UserName.SetLabel(self.uname)
        self.UserName.Move(60, 0)
        self.UserName.Show()
        self.EnterUsername.Hide()
        self.BtnSignUp.Hide()
        self.UploadFile.Show()
        self.DownloadFile.Show()

    def upload_page(self, event):
        self.search_bar.Hide()
        self.searchBtn.Hide()
        self.list_of_files.Hide()
        self.UploadFile.Hide()
        self.DownloadFile.SetSize(120, 20)
        self.DownloadFile.Move(365, 0)
        self.DownloadFile.Show()
        self.BtnSend.Show()
        self.data_to_server.Show()
        self.DataToSendLabel.Show()
        self.BtnSend.Show()
        self.data_to_server.Show()
        self.DataToSendLabel.Show()
        self.list_of_files_lable.Hide()

    def download_page(self, event):
        self.searchBtn.Show()
        self.search_bar.Show()
        self.BtnSend.Hide()
        self.data_to_server.Hide()
        self.DataToSendLabel.Hide()
        self.DownloadFile.Hide()
        self.UploadFile.Hide()
        self.UploadFile.SetSize(120, 20)
        self.UploadFile.Move(365, 0)
        self.UploadFile.Show()
        self.list_of_files.Show()
        self.list_of_files_lable.Show()
        self.initialization_files_for_downloading()
    def before_encrypt_choose(self):
        self.search_bar.Hide()
        self.searchBtn.Hide()
        self.UploadFile.Hide()
        self.DownloadFile.Hide()
        self.BtnSignUp.Hide()
        self.BtnLogin.Hide()
        self.EnterUsername.Hide()
        self.EnterPassword.Hide()
        self.msg.Hide()
        self.MSGLabel.Hide()
        self.data_to_server.Hide()
        self.data_from_server.Hide()
        self.EnterPasswordLabel.Hide()
        self.EnterUsernameLabel.Hide()
        self.DataFromServerLabel.Hide()
        self.DataToSendLabel.Hide()
        self.list_of_files_lable.Hide()
        self.list_of_files.Hide()
        self.BtnSend.Hide()

    def after_encrypt_choose(self):
        self.BtnDP.Hide()
        self.BtnRSA.Hide()
        self.ChooseLabel.Hide()
        self.BtnSignUp.Show()
        self.BtnLogin.Show()
        self.EnterUsername.Show()
        self.EnterPassword.Show()
        self.data_from_server.Show()
        self.EnterPasswordLabel.Show()
        self.EnterUsernameLabel.Show()
        self.DataFromServerLabel.Show()

    def _int_to_bytes(self, n, byteorder="big"):
        # To make shorter
        n &= 0xFFFFFFFF

        # AES key sizes
        aes_key_sizes = [16, 24, 32]

        # Determine the closest AES key size
        closest_key_size = min(aes_key_sizes, key=lambda x: abs(x - n))
        return n.to_bytes(closest_key_size, byteorder)

    def signature(self):
        digital_signature = recv_by_size(self.cli_sock)
        original_message = recv_by_size(self.cli_sock)
        public_key = recv_by_size(self.cli_sock)
        public_key_obj = rsa.PublicKey.load_pkcs1(public_key)
        hash_data = hashlib.sha256(original_message).digest()
        try:
            rsa.verify(hash_data, digital_signature, public_key_obj)
            print("Digital Signature Verification: YES")
        except rsa.VerificationError:
            print("Digital Signature Verification: NO")

    def OnTcpConnectSignUp(self, event):
        if self.EnterUsername.Value == "" or self.EnterPassword.Value == "":
            self.data_from_server.Append("Please enter username and password")
            return
        try:
            self.cli_sock = socket.socket()
            self.cli_sock.connect((self.ip, 33445))
            if self.encrypt_rsa and not self.encrypt_dp:
                send_with_size(self.cli_sock, "ENP~RSA".encode())
                self.rsa_exchange()
            else:
                send_with_size(self.cli_sock, "ENP~DP".encode())
                self.dp_exchange()
            self.listener = threading.Thread(target=self.listen)
            data_to_send = "SUC~" + self.EnterUsername.Value + ":" + self.EnterPassword.Value
            encrypt_data_to_send, iv = self.encypt_using_aes(self.final_key, data_to_send.encode())
            send_with_size(self.cli_sock, encrypt_data_to_send + b"~" + iv)
            self.state = "signup_state"
            self.uname = self.EnterUsername.Value
            self.signature()
            self.after_login_or_signup()
            self.listener.start()
        except Exception as err:
            self.data_from_server.Append("Error while trying to connect: " + str(err))

    def OnTcpConnectLogin(self, event):
        if self.EnterUsername.Value == "" or self.EnterPassword.Value == "":
            self.data_from_server.Append("Please enter username and password")
            return
        try:
            self.cli_sock = socket.socket()
            self.cli_sock.connect((self.ip, 33445))
            if self.encrypt_rsa and not self.encrypt_dp:
                send_with_size(self.cli_sock, "ENP~RSA".encode())
                self.rsa_exchange()
            else:
                send_with_size(self.cli_sock, "ENP~DP".encode())
                self.dp_exchange()

            self.listener = threading.Thread(target=self.listen)
            data_to_send = "LOG~" + self.EnterUsername.Value + ":" + self.EnterPassword.Value
            encrypt_data_to_send, iv = self.encypt_using_aes(self.final_key, data_to_send.encode())
            send_with_size(self.cli_sock, encrypt_data_to_send + b"~" + iv)
            self.state = "login_state"
            self.uname = self.EnterUsername.Value
            self.signature()
            self.after_login_or_signup()
            self.listener.start()
        except Exception as err:
            self.data_from_server.Append("Error while trying to connect: " + str(err))

    def listen(self):
        while True:
            try:
                self.cli_sock.settimeout(1)
                bd, iv = recv_by_size(self.cli_sock).split(b"~")
                byte_data = self.decrypt_using_aes(self.final_key, bd, iv)
                data = byte_data.decode()
                message_raw_data = data
                action = data[:3]
                data = data[4:]
                fields = data.split("~")

                if action == "UFS":
                    self.data_from_server.Append(fields[0])
                elif action == "DFS":

                    end_to_end_download_file(message_raw_data)
                elif action == "SID":
                    all_files = fields[0][1:len(fields[0])-2]
                    self.update_files(all_files)
            except socket.timeout:
                continue
            except socket.error as err:
                self.data_from_server.Append("Listener exit sock exception")
                break

    def update_files(self, all_files):
        try:
            all_files = all_files.split(')')
            for file_data in all_files:
                fields_of_files_for_downloading = file_data[1:]
                fields_of_files_for_downloading = fields_of_files_for_downloading.replace("(", "")
                fields_of_files_for_downloading = fields_of_files_for_downloading.split(',')
                file_to_download = (f"'{os.path.basename(fields_of_files_for_downloading[2])} -> "
                                f"size of file: {fields_of_files_for_downloading[4]} bytes -> "
                                f"id of file: {fields_of_files_for_downloading[0]}")
                if not self.is_file_to_download_exist(file_to_download):
                    self.list_of_files.Append(file_to_download)
        except Exception as e:
            self.data_from_server.Append("there aren't files in our website yet")
            print(e)

    def is_file_to_download_exist(self, file_to_download: str) -> bool:
        for line in self.list_of_files.GetStrings():
            fields_of_line = file_to_download.split('->')
            lines_fields = line.split('->')
            if fields_of_line[0] == lines_fields[0]:
                return True
        return False

    def is_file_exist(self, file_path:str) -> bool:
        return os.path.exists(file_path)

    def popup_msg(self, file_path):
        popup = tk.Tk()
        popup.wm_title("Download Confirmation")

        label = ttk.Label(popup, text=f"Can we download this file from your computer now?\n{file_path}")
        label.pack(pady=10)


        def accept_action():
            print("File download accepted")
            popup.destroy()

        def reject_action():
            print("File download rejected")
            popup.destroy()

        accept_button = ttk.Button(popup, text="Accept", command=accept_action)
        accept_button.pack(side="left", padx=10)

        reject_button = ttk.Button(popup, text="Reject", command=reject_action)
        reject_button.pack(side="right", padx=10)

        popup.mainloop()

    def OnTcpSend(self, event):
        if self.data_to_server != "" and os.path.exists(self.data_to_server.Value):
            try:
                size = os.path.getsize(self.data_to_server.Value)
                with open(self.data_to_server.Value, 'rb') as fn:
                    hashed_data = hashlib.sha256(fn.read()).hexdigest()
                    to_send = "UPF~" + self.uname + "~" + self.data_to_server.Value + "~" + str(hashed_data) + '~' + str(size)
                    encrypt_data_to_send, iv = self.encypt_using_aes(self.final_key, to_send.encode())
                    send_with_size(self.cli_sock, encrypt_data_to_send + b"~" + iv)
            except Exception as err:
                self.data_from_server.Append("Enter on file to download")
            self.data_to_server.Value = ""
        else:
            self.data_from_server.Append("The path is incorrect")


def main():
    app = wx.App(0)
    ip = "192.168.1.135"
    WxChatClient(None, -1, "WxChatClient", ip)
    app.MainLoop()


if __name__ == "__main__":
    main()
