# Bài tập Lập trình Web


# Bài tập An toàn thông tin
# 🛡️ Bài Tập 1: An Toàn và Bảo Mật Thông Tin

**Sinh viên thực hiện:** Hoàng Công Vinh.
**Mã sinh viên:** K235480106100

---

## 1. Tìm hiểu thuật toán mã hóa hiện đại DES và AES

### 1.1. Thuật toán mã hóa DES (Data Encryption Standard)

DES là thuật toán mã hóa khối (block cipher) khóa đối xứng được phát triển vào thập niên 1970. Thuật toán này sử dụng cấu trúc Mạng Feistel. Hiện nay, DES không còn được xem là an toàn do kích thước khóa quá ngắn, dễ bị tấn công vét cạn (brute-force).

**Đặc điểm kỹ thuật:**
* **Kích thước khối dữ liệu (Block size):** 64-bit.
* **Kích thước khóa (Key size):** 64-bit (trong đó 8-bit dùng để kiểm tra tính chẵn lẻ parity, nên khóa thực tế chỉ dài **56-bit**).
* **Số vòng lặp (Rounds):** 16 vòng.

**Quy trình mã hóa:**
1. **Hoán vị khởi tạo (Initial Permutation - IP):** Bản rõ 64-bit đầu vào bị hoán vị vị trí các bit theo một quy tắc cố định.
2. **Chia khối:** Dữ liệu 64-bit được chia thành 2 nửa: Nửa Trái (L0, 32-bit) và Nửa Phải (R0, 32-bit).
3. **16 vòng lặp Feistel:** Tại mỗi vòng i (từ 1 đến 16), dữ liệu được tính toán:
   * L(i) = R(i-1)
   * R(i) = L(i-1) XOR F( R(i-1), K(i) )
   *(Hàm F: Mở rộng R(i-1) lên 48-bit ➔ XOR với khóa vòng K(i) ➔ Nén qua S-box về 32-bit ➔ Hoán vị qua P-box).*
4. **Hoán vị ngược (Inverse IP):** Đổi chỗ L(16) và R(16), ghép thành 64-bit và hoán vị ngược để tạo ra bản mã cuối cùng.

**Quy trình giải mã:**
Sử dụng chính thuật toán mã hóa (cấu trúc Feistel), nhưng **đảo ngược thứ tự các khóa vòng**. Vòng 1 dùng khóa K(16), vòng 2 dùng K(15), ..., vòng 16 dùng K(1).

---

### 1.2. Thuật toán mã hóa AES (Advanced Encryption Standard)

AES được công bố vào năm 2001 để thay thế DES. Đây là chuẩn mã hóa đối xứng an toàn và phổ biến nhất thế giới hiện nay. Thuật toán dựa trên Mạng thay thế - hoán vị (SPN - Substitution-Permutation Network).

**Đặc điểm kỹ thuật:**
* **Kích thước khối (Block size):** Cố định **128-bit** (dữ liệu được xử lý dưới dạng ma trận trạng thái 4x4 byte).
* **Kích thước khóa & Số vòng lặp:** Khóa càng dài, số vòng lặp càng nhiều để tăng cường bảo mật.
  * Khóa 128-bit ➔ 10 vòng.
  * Khóa 192-bit ➔ 12 vòng.
  * Khóa 256-bit ➔ 14 vòng.

**Quy trình mã hóa (Ví dụ hệ 128-bit / 10 vòng):**
1. **Mở rộng khóa (Key Expansion):** Thuật toán sinh ra 11 khóa phụ từ khóa chính ban đầu.
2. **Vòng khởi tạo (Initial Round):** 
   * `AddRoundKey`: XOR ma trận dữ liệu (State) với khóa phụ thứ 0.
3. **9 Vòng lặp chính (Main Rounds):** Mỗi vòng lặp tuần tự qua 4 bước:
   * **SubBytes:** Thay thế từng byte qua bảng S-box (tạo tính hỗn loạn - Confusion).
   * **ShiftRows:** Dịch vòng các byte theo từng hàng (hàng 1 giữ nguyên, hàng 2 dịch 1, hàng 3 dịch 2, hàng 4 dịch 3).
   * **MixColumns:** Trộn dữ liệu toán học theo từng cột (tạo tính khuếch tán - Diffusion).
   * **AddRoundKey:** XOR ma trận hiện tại với khóa phụ thứ i.
4. **Vòng cuối cùng (Final Round - Vòng 10):** Tương tự vòng chính nhưng **bỏ qua bước MixColumns** (`SubBytes` ➔ `ShiftRows` ➔ `AddRoundKey`).

**Quy trình giải mã:**
Áp dụng các hàm ngược của quá trình mã hóa (`InvShiftRows`, `InvSubBytes`, `AddRoundKey`, `InvMixColumns`) và sử dụng các khóa phụ theo thứ tự từ cuối lên đầu.
## 2. Cài đặt thuật toán AES bằng Python

Chương trình sử dụng thư viện `pycryptodome` để mô phỏng quy trình mã hóa và giải mã AES ở chế độ CBC (Cipher Block Chaining).

**Yêu cầu cài đặt:**
`pip install pycryptodome`

**Mã nguồn Python:**
Đã đính kèm trong file 👉 [bai1_aes.py]([bai1_aes.py](https://github.com/IrVinhVn/Bt_Web/tree/main/ATTT/Bai1_AES))

**Kết quả chạy thử nghiệm:**
Chương trình đã thực hiện:
1. Đệm dữ liệu (Padding) đạt chuẩn block size.
2. Sinh Vector khởi tạo (IV) ngẫu nhiên.
3. Mã hóa văn bản và xuất ra định dạng Base64.
4. Tách IV, giải mã và hiển thị lại văn bản gốc thành công.
