import webview
from backend import app
from encryption_handler_ratchet import EncryptionHandler

encryption_handler = EncryptionHandler()

class API:
    def encrypt_message(self, message, recipient_public_key, email):
        return encryption_handler.encrypt_message(message, recipient_public_key, email)

    def decrypt_message(self, encrypted_message, recipient_public_key, email):
        return encryption_handler.decrypt_message(encrypted_message, recipient_public_key, email)

    def generate_keys(self, user_email):
        return encryption_handler.generate_csidh_key_pair(user_email)

    def load_private_key(self, user_email):
        encryption_handler.load_private_key(user_email)

    def verify_signature(self, email, signature, bs, msg, SIGN): 
        return encryption_handler.verify_signature(email, signature, bs, msg, SIGN)
    
    def generate_ephemeral_key(self):
        return encryption_handler.generate_ephemeral_key()
    
    def X3DH_Alice(self, email, IKB, SPKB, OPKB):
        return encryption_handler.X3DH_Alice(email, IKB, SPKB, OPKB)
    
    def X3DH_Bob(self, email, EK, IKA, OPK_id):
        return encryption_handler.X3DH_Bob(email, EK, IKA, OPK_id)
    
    def ratchet_encrypt(self, state, plaintext, AD):
        return encryption_handler.ratchet_encrypt(state, plaintext, AD)

    def ratchet_decrypt(self, state, header, ciphertext, AD):
        return encryption_handler.ratchet_decrypt(state, header, ciphertext, AD)
    
    def encrypt_attachment(self, message, recipient_public_key, user_email):
        return encryption_handler.encrypt_attachment(message, recipient_public_key, user_email)
    
    def decrypt_attachment(self, encrypted_message_base64, recipient_public_key, user_email):
        return encryption_handler.decrypt_attachment(encrypted_message_base64, recipient_public_key, user_email)

if __name__ == '__main__':
    api = API()
    webview.settings['ALLOW_DOWNLOADS'] = True
    webview.create_window('Messaging App', "http://127.0.0.1:5000", js_api=api, width=1200, height=600) 
    webview.start(private_mode=False, debug=True)