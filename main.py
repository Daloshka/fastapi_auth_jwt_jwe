import jwt
import secrets
import base64
from datetime import datetime, timedelta, UTC
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Конфигурация
SECRET_KEY_256 = get_random_bytes(32)
ALGORITHM = "HS256"
JWE_ALGORITHM = "A256KW"
JWE_ENCRYPTION = "A256GCM"


# Функция для генерации JWT токена
def encode_jwt(payload: dict, secret_key: bytes, algorithm: str, expire_minutes: int = 15) -> str:
    payload_copy = payload.copy()
    expire = datetime.now(UTC) + timedelta(minutes=expire_minutes)
    payload_copy.update({"exp": expire, "iat": datetime.now(UTC)})
    token = jwt.encode(payload_copy, secret_key, algorithm=algorithm)
    return token

def decode_jwt(
        token: str | bytes,
        secret_key: bytes = SECRET_KEY_256,
        algorithm: str = JWE_ALGORITHM,
) -> dict:
    decoded = jwt.decode(
        token,
        secret_key,
        algorithms=[algorithm],
    )
    return decoded

# Функция для шифрования JWT токена
def encrypt_jwt_to_jwe(token: str, encryption_key: bytes) -> str:
    cipher = AES.new(encryption_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(token.encode())
    encrypted_token = base64.urlsafe_b64encode(cipher.nonce + tag + ciphertext).decode()
    return encrypted_token


# Функция для дешифровки JWE токена
def decrypt_jwe_to_jwt(jwe_token: str, SECRET_KEY: bytes) -> str:
    decoded_data = base64.urlsafe_b64decode(jwe_token.encode())
    nonce = decoded_data[:16]
    tag = decoded_data[16:32]
    ciphertext = decoded_data[32:]
    cipher = AES.new(SECRET_KEY, AES.MODE_GCM, nonce=nonce)
    jwt_token = cipher.decrypt_and_verify(ciphertext, tag).decode()
    return jwt_token


# Пример использования
payload = {"user_id": 123, "username": "user1", "role": "admin"}

# Генерация JWT токена
jwt_token = encode_jwt(payload, SECRET_KEY_256, ALGORITHM)
print("Generated JWT:", jwt_token)

# Генерация симметричного ключа для шифрования
encryption_key = secrets.token_bytes(32)

# Шифрование JWT токена
encrypted_token = encrypt_jwt_to_jwe(jwt_token, encryption_key)
print("Encrypted JWE:", encrypted_token)

# Расшифровка данных
decrypted_token = decrypt_jwe_to_jwt(encrypted_token, encryption_key)
print("Decrypted JWT:", decrypted_token)

# Декодирование JWT токена
decoded_token = decode_jwt(jwt_token, SECRET_KEY_256, ALGORITHM)
print("Decoded JWT:", decoded_token)
