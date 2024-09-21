import streamlit as st
import hashlib

# Crypto libraries
from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

# Function to encrypt using AES
def encrypt_aes(plaintext, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

# Function to decrypt using AES
def decrypt_aes(ciphertext, key):
    data = base64.b64decode(ciphertext)
    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()

# Function to encrypt using DES
def encrypt_des(plaintext, key):
    plaintext_bytes = pad(plaintext.encode('utf-8'), 8)
    cipher = DES.new(key, DES.MODE_ECB)
    encrypted_bytes = cipher.encrypt(plaintext_bytes)
    return base64.b64encode(encrypted_bytes).decode('utf-8')

# Function to decrypt using DES
def decrypt_des(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(base64.b64decode(ciphertext)), 8)
    return decrypted.decode()

# Function to encrypt using Triple DES (3DES)
def encrypt_3des(plaintext, key):
    plaintext_bytes = pad(plaintext.encode('utf-8'), 8)
    cipher = DES3.new(key, DES3.MODE_ECB)
    encrypted_bytes = cipher.encrypt(plaintext_bytes)
    return base64.b64encode(encrypted_bytes).decode('utf-8')

# Function to decrypt using 3DES
def decrypt_3des(ciphertext, key):
    cipher = DES3.new(key, DES3.MODE_ECB)
    decrypted = unpad(cipher.decrypt(base64.b64decode(ciphertext)), 8)
    return decrypted.decode()

# Function to encrypt using RSA
def encrypt_rsa(plaintext, pubkey):
    key = RSA.import_key(pubkey)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return base64.b64encode(ciphertext).decode()

# Function to decrypt using RSA
def decrypt_rsa(ciphertext, privkey):
    key = RSA.import_key(privkey)
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(base64.b64decode(ciphertext))
    return plaintext.decode()

# Function to generate AES key
def generate_aes_key():
    return base64.b64encode(get_random_bytes(16)).decode('utf-8')

# Function to generate DES key
def generate_des_key():
    return base64.b64encode(get_random_bytes(8)).decode('utf-8')

# Function to generate 3DES key
def generate_3des_key():
    return base64.b64encode(get_random_bytes(16)).decode('utf-8')

# Function to generate RSA keys
def generate_rsa_keys():
    key = RSA.generate(2048)
    priv_key = key.export_key().decode()
    pub_key = key.publickey().export_key().decode()
    return pub_key, priv_key

# Function to calculate MD5 hash
def md5_hash(text):
    return hashlib.md5(text.encode()).hexdigest()

# Function to calculate SHA-256 hash
def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

# Function to encrypt using Caesar Cipher
def encrypt_caesar(plaintext, shift):
    result = ""
    for char in plaintext:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                result += chr((shifted - 97) % 26 + 97)
            else:
                result += chr((shifted - 65) % 26 + 65)
        else:
            result += char
    return result

# Function to decrypt using Caesar Cipher
def decrypt_caesar(ciphertext, shift):
    return encrypt_caesar(ciphertext, -shift)

# Function to load custom CSS
def load_css(file_name):
    with open(file_name) as f:
        st.markdown('<style>{}</style>'.format(f.read()), unsafe_allow_html=True)

# Streamlit app code
def main():
    st.title('Crypto Guard')
    st.sidebar.title('Options')

    load_css('styles.css')  # Load custom CSS

    options = st.sidebar.radio('Choose an option', ('Encrypt', 'Decrypt'))
    algorithm = st.sidebar.selectbox('Choose an algorithm', ('AES', 'DES', '3DES', 'RSA', 'MD5', 'SHA-256', 'Caesar'))

    if options == 'Encrypt':
        if algorithm == 'AES':
            st.subheader('AES Encryption')
            if st.button('Generate AES Key'):
                st.session_state.aes_key = generate_aes_key()
            key = st.text_input('Enter AES Key (16 bytes)', value=st.session_state.get('aes_key', ''))
            plaintext = st.text_area('Enter plaintext', height=10)
            if st.button('Encrypt'):
                if len(base64.b64decode(key)) == 16:
                    ciphertext = encrypt_aes(plaintext, base64.b64decode(key))
                    st.text_area('Encrypted Text', value=ciphertext, height=10)
        
        elif algorithm == 'DES':
            st.subheader('DES Encryption')
            if st.button('Generate DES Key'):
                st.session_state.des_key = generate_des_key()
            key = st.text_input('Enter DES Key (8 bytes)', value=st.session_state.get('des_key', ''))
            plaintext = st.text_area('Enter plaintext', height=10)
            if st.button('Encrypt'):
                if len(base64.b64decode(key)) == 8:
                    ciphertext = encrypt_des(plaintext, base64.b64decode(key))
                    st.text_area('Encrypted Text', value=ciphertext, height=10)
        
        elif algorithm == '3DES':
            st.subheader('3DES Encryption')
            if st.button('Generate 3DES Key'):
                st.session_state['3des_key'] = generate_3des_key()
            key = st.text_input('Enter 3DES Key (16 bytes)', value=st.session_state.get('3des_key', ''))
            plaintext = st.text_area('Enter plaintext', height=10)
            if st.button('Encrypt'):
                if len(base64.b64decode(key)) == 16:
                    ciphertext = encrypt_3des(plaintext, base64.b64decode(key))
                    st.text_area('Encrypted Text', value=ciphertext, height=10)
        
        elif algorithm == 'RSA':
            st.subheader('RSA Encryption')
            if st.button('Generate RSA Keys'):
                pubkey, privkey = generate_rsa_keys()
                st.session_state['rsa_pubkey'] = pubkey
                st.session_state['rsa_privkey'] = privkey
            pubkey = st.text_area('Enter Public Key', value=st.session_state.get('rsa_pubkey', ''))
            plaintext = st.text_area('Enter plaintext', height=10)
            if st.button('Encrypt'):
                if pubkey:
                    ciphertext = encrypt_rsa(plaintext, pubkey)
                    st.text_area('Encrypted Text', value=ciphertext, height=10)

        elif algorithm == 'MD5':
            st.subheader('MD5 Hash')
            plaintext = st.text_area('Enter plaintext', height=10)
            if st.button('Calculate MD5 Hash'):
                if plaintext:
                    md5_hash_value = md5_hash(plaintext)
                    st.text_area('MD5 Hash', value=md5_hash_value, height=10)

        elif algorithm == 'SHA-256':
            st.subheader('SHA-256 Hash')
            plaintext = st.text_area('Enter plaintext', height=10)
            if st.button('Calculate SHA-256 Hash'):
                if plaintext:
                    sha256_hash_value = sha256_hash(plaintext)
                    st.text_area('SHA-256 Hash', value=sha256_hash_value, height=10)

        elif algorithm == 'Caesar':
            st.subheader('Caesar Cipher')
            plaintext = st.text_area('Enter plaintext', height=10)
            shift = st.number_input('Enter shift (0-25)', min_value=0, max_value=25, value=3)
            if st.button('Encrypt'):
                if plaintext:
                    ciphertext = encrypt_caesar(plaintext, shift)
                    st.text_area('Encrypted Text', value=ciphertext, height=10)
            if st.button('Decrypt'):
                if plaintext:
                    plaintext = decrypt_caesar(plaintext, shift)
                    st.text_area('Decrypted Text', value=plaintext, height=10)

    elif options == 'Decrypt':
        if algorithm == 'AES':
            st.subheader('AES Decryption')
            key = st.text_input('Enter AES Key (16 bytes)', value=st.session_state.get('aes_key', ''))
            ciphertext = st.text_area('Enter ciphertext', height=10)
            if st.button('Decrypt'):
                if len(base64.b64decode(key)) == 16 and ciphertext:
                    plaintext = decrypt_aes(ciphertext, base64.b64decode(key))
                    st.text_area('Decrypted Text', value=plaintext, height=10)
        
        elif algorithm == 'DES':
            st.subheader('DES Decryption')
            key = st.text_input('Enter DES Key (8 bytes)', value=st.session_state.get('des_key', ''))
            ciphertext = st.text_area('Enter ciphertext', height=10)
            if st.button('Decrypt'):
                if len(base64.b64decode(key)) == 8 and ciphertext:
                    plaintext = decrypt_des(ciphertext, base64.b64decode(key))
                    st.text_area('Decrypted Text', value=plaintext, height=10)
        
        elif algorithm == '3DES':
            st.subheader('3DES Decryption')
            key = st.text_input('Enter 3DES Key (16 bytes)', value=st.session_state.get('3des_key', ''))
            ciphertext = st.text_area('Enter ciphertext', height=10)
            if st.button('Decrypt'):
                if len(base64.b64decode(key)) == 16 and ciphertext:
                    plaintext = decrypt_3des(ciphertext, base64.b64decode(key))
                    st.text_area('Decrypted Text', value=plaintext, height=10)
        
        elif algorithm == 'RSA':
            st.subheader('RSA Decryption')
            privkey = st.text_area('Enter Private Key', value=st.session_state.get('rsa_privkey', ''))
            ciphertext = st.text_area('Enter ciphertext', height=10)
            if st.button('Decrypt'):
                if privkey and ciphertext:
                    plaintext = decrypt_rsa(ciphertext, privkey)
                    st.text_area('Decrypted Text', value=plaintext, height=10)

if __name__ == '__main__':
    main()