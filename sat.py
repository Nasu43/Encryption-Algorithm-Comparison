import streamlit as st
from Crypto.Cipher import DES, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import time
import pandas as pd
from PIL import Image
import numpy as np

# Function to measure encryption and decryption time
def measure_time(algorithm_name, cipher, encrypt_func, decrypt_func, data):
    start_time = time.time()
    encrypted_data = encrypt_func(cipher, data)
    encryption_time = (time.time() - start_time) * 1e3  # Convert seconds to milliseconds

    start_time = time.time()
    decrypted_data = decrypt_func(cipher, encrypted_data)
    decryption_time = (time.time() - start_time) * 1e3  # Convert seconds to milliseconds

    return encryption_time, decryption_time, decrypted_data

# DES encryption and decryption functions
def des_encrypt(cipher, data):
    return cipher.encrypt(pad(data, DES.block_size))

def des_decrypt(cipher, encrypted_data):
    return unpad(cipher.decrypt(encrypted_data), DES.block_size)

# AES encryption and decryption functions
def aes_encrypt(cipher, data):
    return cipher.encrypt(pad(data, AES.block_size))

def aes_decrypt(cipher, encrypted_data):
    return unpad(cipher.decrypt(encrypted_data), AES.block_size)

# RSA encryption and decryption functions
def rsa_encrypt(cipher, data):
    chunk_size = 214  # OAEP with SHA-256 and MGF1 allows 214 bytes max for 2048 bit key
    encrypted_data = b''.join([cipher.encrypt(data[i:i+chunk_size]) for i in range(0, len(data), chunk_size)])
    return encrypted_data

def rsa_decrypt(cipher, encrypted_data):
    chunk_size = 256  # 2048 bits / 8 bits per byte
    decrypted_data = b''.join([cipher.decrypt(encrypted_data[i:i+chunk_size]) for i in range(0, len(encrypted_data), chunk_size)])
    return decrypted_data

# Main Streamlit app
def main():
    st.title('Encryption Algorithm Comparison')

    input_type = st.radio("Choose input type:", ("Text", "Image"))

    if input_type == "Text":
        message = st.text_area("Enter your message (up to 100 words):", height=200)
    else:
        uploaded_file = st.file_uploader("Choose an image...", type=["jpg", "jpeg", "png"])
    
    if st.button('Encrypt and Decrypt'):
        if input_type == "Text":
            if not message:
                st.warning("Please enter a message to encrypt and decrypt.")
                return
            data = message.encode()
        else:
            if not uploaded_file:
                st.warning("Please upload an image to encrypt and decrypt.")
                return
            image = Image.open(uploaded_file)
            st.image(image, caption='Uploaded Image.', use_column_width=True)
            data = np.array(image).tobytes()

        # Generate keys and ciphers for DES, AES, and RSA
        des_key = get_random_bytes(8)  # DES key must be 8 bytes long
        des_key += bytes([0] * (8 - len(des_key)))  # Pad with zeros if necessary
        des_cipher = DES.new(des_key, DES.MODE_ECB)

        aes_key = get_random_bytes(16)  # AES key can be 16, 24, or 32 bytes long
        aes_cipher = AES.new(aes_key, AES.MODE_ECB)

        rsa_key = RSA.generate(2048)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)

        # Measure times for DES
        des_encryption_time, des_decryption_time, _ = measure_time(
            'DES', des_cipher, des_encrypt, des_decrypt, data)

        # Measure times for AES
        aes_encryption_time, aes_decryption_time, _ = measure_time(
            'AES', aes_cipher, aes_encrypt, aes_decrypt, data)

        # Measure times for RSA
        rsa_encryption_time, rsa_decryption_time, _ = measure_time(
            'RSA', rsa_cipher, rsa_encrypt, rsa_decrypt, data)

        # Display the results
        st.header('Encryption and Decryption Results')

        st.subheader('DES Algorithm')
        st.write("Encryption Time (ms):", f"{des_encryption_time:.10f}")
        st.write("Decryption Time (ms):", f"{des_decryption_time:.10f}")

        st.subheader('AES Algorithm')
        st.write("Encryption Time (ms):", f"{aes_encryption_time:.10f}")
        st.write("Decryption Time (ms):", f"{aes_decryption_time:.10f}")

        st.subheader('RSA Algorithm')
        st.write("Encryption Time (ms):", f"{rsa_encryption_time:.10f}")
        st.write("Decryption Time (ms):", f"{rsa_decryption_time:.10f}")

        # Determine the fastest algorithm for encryption
        fastest_encryption_algorithm = min(
            ('DES', des_encryption_time),
            ('AES', aes_encryption_time),
            ('RSA', rsa_encryption_time),
            key=lambda x: x[1]
        )

        # Determine the fastest algorithm for decryption
        fastest_decryption_algorithm = min(
            ('DES', des_decryption_time),
            ('AES', aes_decryption_time),
            ('RSA', rsa_decryption_time),
            key=lambda x: x[1]
        )

        st.subheader('Fastest Algorithms')

        st.write("Fastest Encryption Algorithm:", fastest_encryption_algorithm[0], "with time:", f"{fastest_encryption_algorithm[1]:.10f} ms")
        st.write("Fastest Decryption Algorithm:", fastest_decryption_algorithm[0], "with time:", f"{fastest_decryption_algorithm[1]:.10f} ms")

        # Create a DataFrame for plotting
        data = {
            'Algorithm': ['DES', 'AES', 'RSA'],
            'Encryption Time (ms)': [des_encryption_time, aes_encryption_time, rsa_encryption_time],
            'Decryption Time (ms)': [des_decryption_time, aes_decryption_time, rsa_decryption_time]
        }
        df = pd.DataFrame(data).set_index('Algorithm')

        # Plotting
        st.subheader('Encryption and Decryption Times (ms)')
        st.write("Encryption Times")
        st.line_chart(df[['Encryption Time (ms)']])

        st.write("Decryption Times")
        st.line_chart(df[['Decryption Time (ms)']])

if __name__ == "__main__":
    main()
