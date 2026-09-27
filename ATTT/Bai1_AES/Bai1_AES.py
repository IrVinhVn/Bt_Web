import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class AESCipher:
    def __init__(self, key):
        # Đảm bảo khóa luôn có độ dài đúng 16 ký tự (128-bit)
        # Nếu nhập ngắn hơn sẽ tự động đệm khoảng trắng, dài hơn sẽ bị cắt bớt
        safe_key = key.ljust(16)[:16]
        self.key = safe_key.encode('utf-8')

    def encrypt(self, raw_text):
        raw_bytes = raw_text.encode('utf-8')
        padded_data = pad(raw_bytes, AES.block_size)
        
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        encrypted_bytes = cipher.encrypt(padded_data)
        return base64.b64encode(iv + encrypted_bytes).decode('utf-8')

    def decrypt(self, encrypted_text):
        encrypted_bytes = base64.b64decode(encrypted_text)
        
        iv = encrypted_bytes[:AES.block_size]
        cipher_text = encrypted_bytes[AES.block_size:]
        
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(cipher_text)
        decrypted_bytes = unpad(decrypted_padded, AES.block_size)
        
        return decrypted_bytes.decode('utf-8')

# ==========================================
# CHẠY CHƯƠNG TRÌNH VỚI NHẬP LIỆU
# ==========================================
if __name__ == "__main__":
    print("=== CHƯƠNG TRÌNH MÃ HÓA AES ===")
    
    # 1. Cho người dùng nhập khóa bí mật
    user_key = input("Nhập khóa bí mật (mật khẩu): ")
    aes = AESCipher(user_key)
    
    # 2. Cho người dùng nhập văn bản cần mã hóa
    message = input("Nhập văn bản cần mã hóa: ")
    
    print("\n--- ĐANG XỬ LÝ ---")
    print("1. Bản rõ ban đầu   :", message)
    
    # Thực hiện mã hóa
    encrypted = aes.encrypt(message)
    print("2. Bản mã (Base64) :", encrypted)
    
    # Thực hiện giải mã
    try:
        decrypted = aes.decrypt(encrypted)
        print("3. Sau khi giải mã :", decrypted)
    except Exception as e:
        print("Lỗi giải mã. Nguyên nhân:", e)