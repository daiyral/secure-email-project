import sys
from PyQt6.QtWidgets import QApplication, QWidget, QPushButton, QToolTip, QMessageBox, QMainWindow, QVBoxLayout, QTextEdit, QLabel
from PyQt6.QtGui import QFont
from merklehellman import MerkleHellman
from frog import Frog
from elgamal import ElGamal
import numpy as np
import paramaters

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
        # k = np.empty(16, dtype=np.int8)
        # for i in range(0, 16):
        #     k[i] = i
        self.intKey=self.frog.makeKey(self.merkle_helman.get_public_key())
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
        arr = np.empty(len(msg), dtype=np.int8)
        i = 0
        for ch in msg:
            arr[i] = ch
            i += 1
        
        print("my text is ", arr)
        self.cipherText=self.frog.frogEncrypt(arr, self.intKey.keyE)
        print("my encrypted text is ",self.cipherText)
        self.email_encrypted.setText("cipherText")
        
    def decrypt_msg(self):
        plainText=self.frog.frogDecrypt(self.cipherText, self.intKey.keyD)
        string = ""
        for i in range(len(plainText)):
            string += chr(plainText[i]).encode("utf-8").decode()
        print("decrypted: ", plainText)
        print("msg was = ", string)
        
if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = Gui()
    sys.exit(app.exec())