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
## 1.3. Cài đặt thuật toán AES bằng Python

Chương trình sử dụng thư viện `pycryptodome` để mô phỏng quy trình mã hóa và giải mã AES ở chế độ CBC (Cipher Block Chaining).

**Yêu cầu cài đặt:**
`pip install pycryptodome`

**Mã nguồn Python:**
Đã đính kèm trong file 👉 [bai1_AES](https://github.com/IrVinhVn/Bt_Web/tree/main/ATTT/Bai1_AES)

**Kết quả chạy thử nghiệm:**
Chương trình đã thực hiện:
1. Đệm dữ liệu (Padding) đạt chuẩn block size.
2. Sinh Vector khởi tạo (IV) ngẫu nhiên.
3. Mã hóa văn bản và xuất ra định dạng Base64.
4. Tách IV, giải mã và hiển thị lại văn bản gốc thành công.

---

## 2. Tìm hiểu thuật toán mã hóa bất đối xứng RSA

RSA (Rivest–Shamir–Adleman) là một trong những thuật toán mã hóa khóa công khai (bất đối xứng) đầu tiên và được sử dụng rộng rãi nhất hiện nay. Khác với mã hóa đối xứng (DES/AES) dùng chung 1 khóa, hệ mật mã bất đối xứng sử dụng một cặp khóa: **Khóa công khai (Public Key)** để mã hóa và **Khóa bí mật (Private Key)** để giải mã. 

Sức mạnh bảo mật của RSA dựa trên độ khó của bài toán toán học: Rất dễ để nhân hai số nguyên tố lớn với nhau, nhưng cực kỳ khó (gần như không thể với máy tính hiện tại) để từ tích số đó phân tích ngược lại ra hai số nguyên tố ban đầu.

### 2.1. Nguyên lý sinh cặp khóa (Key Generation)

Quy trình tạo ra cặp khóa công khai và khóa bí mật trải qua 5 bước toán học sau:

1. **Chọn số nguyên tố:** Chọn 2 số nguyên tố phân biệt rất lớn, gọi là `p` và `q` (thường được sinh ngẫu nhiên).
2. **Tính Module (n):** Tính `n = p * q`. Số `n` này sẽ được dùng làm module cho cả hai khóa (độ dài của `n` chính là độ dài của khóa RSA, ví dụ 2048-bit).
3. **Tính hàm phi Euler (φ):** Tính giá trị `phi(n) = (p - 1) * (q - 1)`.
4. **Chọn khóa công khai (e):** Chọn một số nguyên dương `e` thỏa mãn 2 điều kiện:
   * `1 < e < phi(n)`.
   * `e` và `phi(n)` là hai số nguyên tố cùng nhau (Ước chung lớn nhất bằng 1).
   *(Thông thường, `e` được chọn là 65537 để tối ưu tốc độ tính toán).*
5. **Tính khóa bí mật (d):** Tìm số `d` sao cho `d` là nghịch đảo nhân của `e` theo module `phi(n)`. 
   * Công thức toán học: `(d * e) mod phi(n) = 1`. 
   * *(Người ta thường dùng thuật toán Euclid mở rộng để tính ra d).*

**Tổng kết cặp khóa:**
* **Khóa công khai (Public Key):** Là cặp số `(n, e)`. Bất kỳ ai cũng có thể biết khóa này để gửi tin nhắn bảo mật cho bạn.
* **Khóa bí mật (Private Key):** Là cặp số `(n, d)`. Chỉ duy nhất bạn được giữ kín để mở tin nhắn. Các giá trị `p`, `q` và `phi(n)` cũng phải được hủy bỏ hoặc giữ bí mật.

### 2.2. Quy trình mã hóa và giải mã

Giả sử Alice muốn gửi một tin nhắn bảo mật (bản rõ `M`) cho Bob.

* **Quy trình mã hóa (Encryption):** 
  Alice sử dụng Khóa công khai `(n, e)` của Bob để tạo ra bản mã `C` theo công thức:
  **C = M^e mod n**
  *(Lúc này, dù tin nhắn bị chặn trên đường truyền, hacker không thể đọc được vì không có khóa bí mật).*

* **Quy trình giải mã (Decryption):** 
  Bob nhận được bản mã `C`. Bob sử dụng Khóa bí mật `(n, d)` của mình để tính ngược lại ra bản rõ `M`:
  **M = C^d mod n**
### 3.3. Các mô hình áp dụng thuật toán RSA

Dựa vào cách kết hợp và sử dụng cặp khóa, RSA có thể giải quyết các bài toán về bảo mật và xác thực khác nhau:

*   **Mô hình mã hóa bảo mật (Xác thực người nhận):**
    *   *Cách hoạt động:* Người gửi (Alice) dùng **Khóa công khai** của người nhận (Bob) để mã hóa thông điệp. Bob sau khi nhận được sẽ dùng **Khóa bí mật** của chính mình để giải mã.
    *   *Ý nghĩa:* Đảm bảo tính bí mật (Confidentiality). Chỉ có người nhận hợp pháp (Bob) mới có thể đọc được dữ liệu.

*   **Mô hình chữ ký số (Xác thực người gửi):**
    *   *Cách hoạt động:* Người gửi (Alice) dùng **Khóa bí mật** của chính mình để mã hóa dữ liệu (thực tế thường là mã hóa giá trị băm Hash của dữ liệu). Người nhận (Bob) dùng **Khóa công khai** của Alice để giải mã và đối chiếu.
    *   *Ý nghĩa:* Đảm bảo tính xác thực và chống chối bỏ (Authentication & Non-repudiation). Bob chắc chắn rằng thông điệp này được gửi từ chính Alice và không bị kẻ gian giả mạo.

*   **Mô hình kết hợp (Xác thực cả hai chiều):**
    *   *Cách hoạt động:* Alice ký chữ ký số vào thông điệp bằng **Khóa bí mật của Alice**, sau đó mã hóa toàn bộ khối dữ liệu đó bằng **Khóa công khai của Bob**. Khi nhận được, Bob dùng **Khóa bí mật của Bob** để giải mã lấy gói dữ liệu, rồi dùng **Khóa công khai của Alice** để xác thực chữ ký.
    *   *Ý nghĩa:* Đạt được tính bảo mật toàn diện: Gửi đi an toàn tuyệt đối và xác minh chính xác danh tính người gửi.

---

### 3. So sánh thời gian mã hóa/giải mã của RSA và AES

| Tiêu chí | Mã hóa đối xứng (AES) | Mã hóa bất đối xứng (RSA) |
| :--- | :--- | :--- |
| **Bản chất phép toán** | Phép toán logic cơ bản, dịch bit, ma trận đơn giản. | Phép toán số học module lũy thừa với các số nguyên tố khổng lồ. |
| **Tốc độ (Hiệu năng)** | **Rất nhanh.** Nhanh hơn RSA từ hàng trăm đến hàng nghìn lần. | **Rất chậm.** Tiêu tốn cực kỳ nhiều tài nguyên tính toán của CPU. |
| **Kích thước đầu vào** | Có thể mã hóa lượng dữ liệu khổng lồ vô hạn (Video, File lớn). | Bị giới hạn kích thước (Dữ liệu đầu vào phải nhỏ hơn độ dài khóa). |
| **Mục đích tối ưu** | Dùng để mã hóa dữ liệu thực tế (Bulk Encryption). | Dùng để trao đổi khóa và xác thực danh tính. |

---

### 4. Sự kết hợp sức mạnh giữa RSA và AES (Mã hóa lai - Hybrid Encryption)

Vì AES gặp khó khăn trong việc gửi khóa bí mật đi an toàn qua mạng, còn RSA lại quá chậm để mã hóa những file dung lượng lớn, hệ thống bảo mật hiện đại (như SSL/TLS cho web HTTPS, SSH, hay PGP) đã kết hợp cả hai thuật toán này thành **Hệ mật mã lai**:

**Quy trình hoạt động kết hợp:**
1. **Sinh khóa phiên (Session Key):** Máy tính của người gửi tự động tạo ra một khóa AES dùng một lần (rất nhanh).
2. **Mã hóa dữ liệu bằng AES:** Sử dụng khóa AES vừa tạo để mã hóa toàn bộ file dữ liệu (Giải quyết điểm yếu tốc độ của RSA).
3. **Bọc khóa bằng RSA:** Người gửi dùng Khóa công khai RSA của người nhận để mã hóa chính cái "khóa AES" kia (Giải quyết điểm yếu trao đổi khóa của AES).
4. **Truyền đi:** Người gửi gửi cả hai phần (Dữ liệu đã mã hóa + Khóa phiên đã mã hóa) cho người nhận.
5. **Giải mã:** Người nhận dùng Khóa bí mật RSA của mình để mở gói lấy ra "Khóa phiên AES", sau đó dùng Khóa phiên AES để giải mã lấy file dữ liệu gốc.
