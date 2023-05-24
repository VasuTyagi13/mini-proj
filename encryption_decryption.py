import string
import hashlib, math

# Caesar Cipher
def caesar_encrypt(plain_text, key):
    encrypted_text = ""
    for char in plain_text:
        if char.isalpha():
            if char.isupper():
                encrypted_text += chr((ord(char) - ord('A') + key) % 26 + ord('A'))
            else:
                encrypted_text += chr((ord(char) - ord('a') + key) % 26 + ord('a'))
        else:
            encrypted_text += char
    return encrypted_text


def caesar_decrypt(cipher_text, key):
    return caesar_encrypt(cipher_text, -key)


# Playfair Cipher
def playfair_generate_matrix(key):
    key = key.upper().replace("J", "I")
    key = key + string.ascii_uppercase
    matrix = []
    for char in key:
        if char not in matrix:
            matrix.append(char)
    return matrix


def playfair_generate_pairs(text):
    pairs = []
    i = 0
    while i < len(text):
        if i == len(text) - 1 or text[i] == text[i + 1]:
            pairs.append((text[i], 'X'))
            i += 1
        else:
            pairs.append((text[i], text[i + 1]))
            i += 2
    return pairs


def playfair_get_position(matrix, char):
    row = col = 0
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                row, col = i, j
                break
    return row, col


def playfair_encrypt(plain_text, key):
    plain_text = plain_text.upper().replace("J", "I")
    matrix = playfair_generate_matrix(key)
    pairs = playfair_generate_pairs(plain_text)
    encrypted_text = ""
    for pair in pairs:
        row1, col1 = playfair_get_position(matrix, pair[0])
        row2, col2 = playfair_get_position(matrix, pair[1])
        if row1 == row2:
            encrypted_text += matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            encrypted_text += matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
        else:
            encrypted_text += matrix[row1][col2] + matrix[row2][col1]
    return encrypted_text


def playfair_decrypt(cipher_text, key):
    matrix = playfair_generate_matrix(key)
    pairs = playfair_generate_pairs(cipher_text)
    decrypted_text = ""
    for pair in pairs:
        row1, col1 = playfair_get_position(matrix, pair[0])
        row2, col2 = playfair_get_position(matrix, pair[1])
        if row1 == row2:
            decrypted_text += matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            decrypted_text += matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
        else:
            decrypted_text += matrix[row1][col2] + matrix[row2][col1]
    return decrypted_text


# Monoalphabetic Cipher
def create_monoalphabetic_key():
    shuffled_letters = list(string.ascii_uppercase)
    random.shuffle(shuffled_letters)
    return ''.join(shuffled_letters)


def monoalphabetic_encrypt(plain_text, key):
    encrypted_text = ""
    for char in plain_text:
        if char.isalpha():
            if char.isupper():
                encrypted_text += key[ord(char) - ord('A')]
            else:
                encrypted_text += key[ord(char) - ord('a')].lower()
        else:
            encrypted_text += char
    return encrypted_text


def monoalphabetic_decrypt(cipher_text, key):
    decrypted_text = ""
    for char in cipher_text:
        if char.isalpha():
            if char.isupper():
                decrypted_text += chr(key.index(char) + ord('A'))
            else:
                decrypted_text += chr(key.index(char.lower()) + ord('a'))
        else:
            decrypted_text += char
    return decrypted_text


# Polyalphabetic Cipher (Vigenere Cipher)
def vigenere_encrypt(plain_text, key):
    encrypted_text = ""
    key = key.upper()
    key_length = len(key)
    for i, char in enumerate(plain_text):
        if char.isalpha():
            if char.isupper():
                encrypted_text += chr((ord(char) + ord(key[i % key_length]) - 2 * ord('A')) % 26 + ord('A'))
            else:
                encrypted_text += chr((ord(char) + ord(key[i % key_length]) - 2 * ord('a')) % 26 + ord('a'))
        else:
            encrypted_text += char
    return encrypted_text


def vigenere_decrypt(cipher_text, key):
    decrypted_text = ""
    key = key.upper()
    key_length = len(key)
    for i, char in enumerate(cipher_text):
        if char.isalpha():
            if char.isupper():
                decrypted_text += chr((ord(char) - ord(key[i % key_length]) + 26) % 26 + ord('A'))
            else:
                decrypted_text += chr((ord(char) - ord(key[i % key_length]) + 26) % 26 + ord('a'))
        else:
            decrypted_text += char
    return decrypted_text


# Vernam Cipher (One-Time Pad)
def vernam_encrypt(plain_text, key):
    encrypted_text = ""
    key = key.upper()
    key_length = len(key)
    for i, char in enumerate(plain_text):
        if char.isalpha():
            if char.isupper():
                encrypted_text += chr((ord(char) + ord(key[i % key_length]) - 2 * ord('A')) % 26 + ord('A'))
            else:
                encrypted_text += chr((ord(char) + ord(key[i % key_length]) - 2 * ord('a')) % 26 + ord('a'))
        else:
            encrypted_text += char
    return encrypted_text


def vernam_decrypt(cipher_text, key):
    return vernam_encrypt(cipher_text, key)


# Hill Cipher
def matrix_multiply(matrix1, matrix2):
    result = [[0] * len(matrix2[0]) for _ in range(len(matrix1))]
    for i in range(len(matrix1)):
        for j in range(len(matrix2[0])):
            for k in range(len(matrix2)):
                result[i][j] += matrix1[i][k] * matrix2[k][j]
            result[i][j] %= 26
    return result


def matrix_inverse(matrix):
    determinant = matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]
    inverse_determinant = pow(determinant, -1, 26)
    inverse = [[0] * 2 for _ in range(2)]
    inverse[0][0] = matrix[1][1] * inverse_determinant % 26
    inverse[0][1] = (-matrix[0][1]) * inverse_determinant % 26
    inverse[1][0] = (-matrix[1][0]) * inverse_determinant % 26
    inverse[1][1] = matrix[0][0] * inverse_determinant % 26
    return inverse


def hill_encrypt(plain_text, key):
    plain_text = plain_text.upper().replace(" ", "")
    key = [[ord(char) - ord('A') for char in row] for row in key]
    key_inverse = matrix_inverse(key)
    block_size = len(key)
    encrypted_text = ""
    for i in range(0, len(plain_text), block_size):
        block = [ord(char) - ord('A') for char in plain_text[i:i + block_size]]
        if len(block) < block_size:
            block += [0] * (block_size - len(block))
        encrypted_block = matrix_multiply([block], key)
        encrypted_block = [(num % 26) + ord('A') for num in encrypted_block[0]]
        encrypted_text += ''.join(chr(num) for num in encrypted_block)
    return encrypted_text


def hill_decrypt(cipher_text, key):
    key = [[ord(char) - ord('A') for char in row] for row in key]
    key_inverse = matrix_inverse(key)
    block_size = len(key)
    decrypted_text = ""
    for i in range(0, len(cipher_text), block_size):
        block = [ord(char) - ord('A') for char in cipher_text[i:i + block_size]]
        decrypted_block = matrix_multiply([block], key_inverse)
        decrypted_block = [(num % 26) + ord('A') for num in decrypted_block[0]]
        decrypted_text += ''.join(chr(num) for num in decrypted_block)
    return decrypted_text


# Columnar Cipher
def columnar_encrypt(plain_text, key):
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    encrypted_text = ""
    for i in key_order:
        j = i
        while j < len(plain_text):
            encrypted_text += plain_text[j]
            j += len(key)
    return encrypted_text


def columnar_decrypt(cipher_text, key):
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    column_length = math.ceil(len(cipher_text) / len(key))
    padding_length = column_length * len(key) - len(cipher_text)
    plain_text = ""
    k = 0
    for i in range(column_length):
        for j in key_order:
            if k < len(cipher_text):
                plain_text += cipher_text[j * column_length + i]
                k += 1
        if padding_length > 0:
            padding_length -= 1
        else:
            break
    return plain_text


# Transposition Cipher
def transposition_encrypt(plain_text, key):
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    encrypted_text = ""
    for i in key_order:
        j = i
        while j < len(plain_text):
            encrypted_text += plain_text[j]
            j += len(key)
    return encrypted_text


def transposition_decrypt(cipher_text, key):
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    column_length = math.ceil(len(cipher_text) / len(key))
    padding_length = column_length * len(key) - len(cipher_text)
    plain_text = ""
    k = 0
    for i in range(column_length):
        for j in key_order:
            if k < len(cipher_text):
                plain_text += cipher_text[j * column_length + i]
                k += 1
        if padding_length > 0:
            padding_length -= 1
        else:
            break
    return plain_text


# Hashing
def md5_hash(plain_text):
    hash_object = hashlib.md5(plain_text.encode())
    return hash_object.hexdigest()


def sha1_hash(plain_text):
    hash_object = hashlib.sha1(plain_text.encode())
    return hash_object.hexdigest()


def sha256_hash(plain_text):
    hash_object = hashlib.sha256(plain_text.encode())
    return hash_object.hexdigest()


def main():
    while True:
        print("1. Caesar Cipher")
        print("2. Playfair Cipher")
        print("3. Monoalphabetic Cipher")
        print("4. Polyalphabetic Cipher (Vigenere Cipher)")
        print("5. Vernam Cipher")
        print("6. Hill Cipher")
        print("7. Columnar Cipher")
        print("8. Transposition Cipher")
        print("9. Hashing")
        print("0. Exit")
        choice = input("Enter your choice: ")

        if choice == '0':
            break

        if choice in ['1', '2', '3', '4', '5', '6', '7', '8', '9']:
            plain_text = input("Enter the plain text: ")

        if choice == '1':
            key = int(input("Enter the key for Caesar Cipher: "))
            caesar_encrypted = caesar_encrypt(plain_text, key)
            print("Caesar Cipher (Encrypted):", caesar_encrypted)
            caesar_decrypted = caesar_decrypt(caesar_encrypted, key)
            print("Caesar Cipher (Decrypted):", caesar_decrypted)

        elif choice == '2':
            key = input("Enter the key for Playfair Cipher: ")
            playfair_encrypted = playfair_encrypt(plain_text, key)
            print("Playfair Cipher (Encrypted):", playfair_encrypted)
            playfair_decrypted = playfair_decrypt(playfair_encrypted, key)
            print("Playfair Cipher (Decrypted):", playfair_decrypted)

        elif choice == '3':
            monoalphabetic_key = create_monoalphabetic_key()
            print("Monoalphabetic Key:", monoalphabetic_key)
            monoalphabetic_encrypted = monoalphabetic_encrypt(plain_text, monoalphabetic_key)
            print("Monoalphabetic Cipher (Encrypted):", monoalphabetic_encrypted)
            monoalphabetic_decrypted = monoalphabetic_decrypt(monoalphabetic_encrypted, monoalphabetic_key)
            print("Monoalphabetic Cipher (Decrypted):", monoalphabetic_decrypted)

        elif choice == '4':
            key = input("Enter the key for Vigenere Cipher: ")
            vigenere_encrypted = vigenere_encrypt(plain_text, key)
            print("Vigenere Cipher (Encrypted):", vigenere_encrypted)
            vigenere_decrypted = vigenere_decrypt(vigenere_encrypted, key)
            print("Vigenere Cipher (Decrypted):", vigenere_decrypted)

        elif choice == '5':
            key = input("Enter the key for Vernam Cipher: ")
            vernam_encrypted = vernam_encrypt(plain_text, key)
            print("Vernam Cipher (Encrypted):", vernam_encrypted)
            vernam_decrypted = vernam_decrypt(vernam_encrypted, key)
            print("Vernam Cipher (Decrypted):", vernam_decrypted)

        elif choice == '6':
            key = [[int(num) for num in input("Enter the key for Hill Cipher (separated by spaces): ").split()] for _ in range(2)]
            hill_encrypted = hill_encrypt(plain_text, key)
            print("Hill Cipher (Encrypted):", hill_encrypted)
            hill_decrypted = hill_decrypt(hill_encrypted, key)
            print("Hill Cipher (Decrypted):", hill_decrypted)

        elif choice == '7':
            key = input("Enter the key for Columnar Cipher: ")
            columnar_encrypted = columnar_encrypt(plain_text, key)
            print("Columnar Cipher (Encrypted):", columnar_encrypted)
            columnar_decrypted = columnar_decrypt(columnar_encrypted, key)
            print("Columnar Cipher (Decrypted):", columnar_decrypted)

        elif choice == '8':
            key = input("Enter the key for Transposition Cipher: ")
            transposition_encrypted = transposition_encrypt(plain_text, key)
            print("Transposition Cipher (Encrypted):", transposition_encrypted)
            transposition_decrypted = transposition_decrypt(transposition_encrypted, key)
            print("Transposition Cipher (Decrypted):", transposition_decrypted)

        elif choice == '9':
            print("1. MD5")
            print("2. SHA1")
            print("3. SHA256")
            hash_choice = input("Enter the hash algorithm: ")
            if hash_choice == '1':
                md5 = md5_hash(plain_text)
                print("MD5:", md5)
            elif hash_choice == '2':
                sha1 = sha1_hash(plain_text)
                print("SHA1:", sha1)
            elif hash_choice == '3':
                sha256 = sha256_hash(plain_text)
                print("SHA256:", sha256)

        print()

if __name__ == '__main__':
    main()
