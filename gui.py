import random
import sys
from PyQt6.QtWidgets import QApplication, QWidget, QPushButton, QToolTip, QMessageBox, QMainWindow, QVBoxLayout, QTextEdit, QLabel
from PyQt6.QtGui import QFont
from merklehellman import MerkleHellman
from frog import Frog
from elgamal import ElGamal
import numpy as np
import paramaters
import cfb_mode
import os

class Gui(QMainWindow):

    __instance = None

    def __init__(self):
        super().__init__()
        """ Virtually private constructor. """
        if Gui.__instance != None:
            raise Exception("This class is a singleton!")
        else:
            Gui.__instance = self
        
        self.setWindowTitle('Mail Encryptor')

        self.setGeometry(200, 100, 200, 400)  # left, top , width , height
        self.font = QFont("Helvetica", 15)
        self.main_vbox = QVBoxLayout()
        self.email_input = None
        self.email_enc_btn = None
        self.email_dec_output = None
        self.public_params_lbl = None
        self.email_encrypted = None
        self.email_dec_btn = None
        self.email_decrypted = None
        self.frog = Frog()
        self.merkle_helman = MerkleHellman()
        self.el_gamal_signature = ElGamal()
        self.encrypted_msg = None
        self.iv = [0] * paramaters.BLOCK_SIZE
        for i in range(paramaters.BLOCK_SIZE):
            self.iv[i] = i
        self.k = [0]* paramaters.BLOCK_SIZE
        for i in range(paramaters.BLOCK_SIZE):
            self.k[i] = random.randint(0, 255)
        self.intKey=self.frog.makeKey(self.k)
        self.k_enc = self.merkle_helman.encrypt(self.k)
        # self.intKey_enc = self.frog.makeKey(self.k).keyE
        # for i in range(len(self.intKey.keyE)):
        #     self.intKey_enc[i].BombPermu = self.merkle_helman.encrypt(self.intKey.keyE[i].BombPermu)
        #     self.intKey_enc[i].SubstPermu = self.merkle_helman.encrypt(self.intKey.keyE[i].SubstPermu)
        #     self.intKey_enc[i].xorBu = self.merkle_helman.encrypt(self.intKey.keyE[i].xorBu)
        
        self.set_encrypt_section()
        self.set_decrypt_section()
        window = QWidget()
        self.setCentralWidget(window)
        window.setLayout(self.main_vbox)
        self.show()
        
    def set_encrypt_section(self):
        label = QLabel("Input Section")
        label.setFont(self.font)
        self.email_input = QTextEdit()
        self.email_input.setFont(self.font)
        self.email_input.setPlaceholderText("Enter your e-mail")
        self.email_enc_btn = QPushButton("Encrypt")
        self.email_enc_btn.clicked.connect(self.encrypt_msg)
        self.public_params_lbl = QLabel("Diffie-Hellman Key Public Params: public key={pub_key}, private key={private_key}".format(pub_key="None", private_key="None"))
        self.public_params_lbl.setFont(self.font)
        self.email_encrypted = QTextEdit()
        self.email_encrypted.setFont(self.font)
        self.email_encrypted.setPlaceholderText("Ecrypted email")
        self.email_encrypted.setEnabled(False)
        self.main_vbox.addWidget(label)
        self.main_vbox.addWidget(self.email_input)
        self.main_vbox.addWidget(self.email_enc_btn)
        self.main_vbox.addWidget(self.public_params_lbl)
        self.main_vbox.addWidget(self.email_encrypted)
        
    
    def set_decrypt_section(self):
        self.email_dec_btn = QPushButton("Decrypt")
        self.email_dec_btn.clicked.connect(self.decrypt_msg)
        self.email_decrypted = QTextEdit()
        self.email_decrypted.setFont(self.font)
        self.email_decrypted.setPlaceholderText("Decrypted email")
        self.email_decrypted.setEnabled(False)
        self.main_vbox.addWidget(self.email_dec_btn)
        self.main_vbox.addWidget(self.email_decrypted)
        
    def encrypt_msg(self):
        msg = self.email_input.toPlainText()
        msg = bytes(msg, 'utf-8')
        arr = [0]*len(msg)
        self.encrypted_msg = [0]*len(msg)
        i = 0
        for ch in msg:
            arr[i] = ch
            i += 1
        self.encrypted_msg = cfb_mode.encrypt(self.frog.frogEncrypt, self.iv, self.intKey.keyE, arr)
        
        print("my encrypted text is ", self.encrypted_msg)
        # string = ""
        # for i in range(len(self.encrypted_msg)):
        #     string += chr(self.encrypted_msg[i]).encode().decode()
        # # print("my encrypted text is ",self.encrypted_msg)
        # self.email_encrypted.setText(string)
        
    def decrypt_msg(self):
        
        k = self.merkle_helman.decrypt(self.k_enc)
        for i in range(len(k)):
            k[i] = int(k[i]/2)
        intKey = self.frog.makeKey(k)
        pText = cfb_mode.decrypt(self.frog.frogEncrypt, self.iv, intKey.keyE, self.encrypted_msg)
        string = ""
        for i in range(len(pText)):
            string += chr(pText[i]).encode("utf-8").decode()
        self.email_decrypted.setText(string)
        
if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = Gui()
    sys.exit(app.exec())