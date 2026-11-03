# PVE Abuse Guard 🛡️

**Hệ thống phát hiện đào coin (CPU Crypto Mining Detector) cho hạ tầng Proxmox VE**  
Thiết kế chuyên biệt cho các nhà cung cấp dịch vụ Cloud, VPS và Dedicated Server.

---

## 🌟 Tính Năng Nổi Bật

- **Zero-Disk Footprint (Thuần In-Memory):** Hoàn toàn **không ghi database hay file rác** xuống ổ đĩa của server Proxmox. Mọi số liệu mẫu và trạng thái vi phạm được theo dõi trong RAM (`< 25MB RAM`).
- **Hoàn toàn Agentless:** Giám sát từ phía Host qua Proxmox REST API nội bộ (`127.0.0.1:8006`). Không cần cài đặt bất kỳ agent hay phần mềm nào vào máy ảo của khách hàng, đảm bảo tính riêng tư và bảo mật.
- **Quyền hạn tối thiểu (Least Privilege):** Chỉ yêu cầu API Token quyền chỉ đọc (`PVEAuditor`).
- **Phát hiện chuẩn xác (Sliding Window):** Bắt các trường hợp CPU $\ge 90\%$ liên tục trong $\ge 30\text{ phút}$, tích hợp cơ chế chống nhiễu (cho phép dung sai nếu CPU tụt thoáng qua).
- **Cảnh báo Discord Webhook chuyên nghiệp:**
  - Rich Embeds hiển thị trực quan: Tên VM, VMID, Node, CPU hiện tại, CPU trung bình trong 30 phút, RAM, Uptime và link mở trực tiếp trên Proxmox Web UI.
  - Màu sắc phân loại: 🔴 Đỏ cho Critical ($\ge 98\%$), 🟠 Cam cho Warning ($\ge 90\%$), 🟢 Xanh lá cho Resolved (hạ nhiệt).
  - **Chống spam & Cooldown:** Tự động khóa cảnh báo lặp lại cho cùng 1 VM trong thời gian Cooldown (mặc định 60 phút).
  - **Tự động xử lý Rate Limit (HTTP 429):** Tự động đọc header `Retry-After` của Discord để hoãn và gửi lại mượt mà, không làm rơi rớt thông báo.
  - **Thông báo hồi phục (Resolved):** Khi VM hạ nhiệt về bình thường đủ 2 chu kỳ liên tiếp, tự động gửi thông báo "Đã hết vi phạm".
- **Can thiệp tự động (Tùy chọn, Mặc định TẮT):** Có chế độ `dry-run` an toàn. Nếu bật, có thể tự động `suspend` hoặc `stop` VM sau $N$ chu kỳ vi phạm kéo dài, kèm danh sách Whitelist bảo vệ các VM quan trọng.

---

## 📋 Yêu Cầu Hệ Thống

- Proxmox VE 7.x hoặc 8.x (chạy trực tiếp trên node Proxmox).
- Python 3.9+ (mặc định Proxmox VE 7/8 đã có sẵn Python 3.9 / 3.11).
- Kết nối mạng ra ngoài để gửi Discord Webhook.

---

## 🚀 Hướng Dẫn Cài Đặt Trên Server Proxmox VE

### Bước 1: Tạo API Token Quyền Chỉ Đọc (`PVEAuditor`) Trên Proxmox

Bạn có thể tạo nhanh bằng dòng lệnh trên node Proxmox qua SSH:

```bash
# 1. Tạo user riêng cho monitor (nếu chưa có)
pveum user add abuse-monitor@pam -comment "User giam sat lam dung"

# 2. Gán quyền chỉ đọc PVEAuditor trên toan bo he thong
pveum acl modify / -user abuse-monitor@pam -role PVEAuditor

# 3. Tao API Token khong co han
pveum user token add abuse-monitor@pam pve-guard -privsep 0
```

> [!IMPORTANT]
> Sau lệnh số 3, Proxmox sẽ in ra một giá trị bí mật dạng `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`. Hãy **sao chép lại ngay** giá trị này (đây là `token_value`).

---

### Bước 2: Tải Mã Nguồn Và Cài Đặt Môi Trường

Tại terminal của server Proxmox:

```bash
# Tạo thư mục làm việc tại /opt
mkdir -p /opt/pve-abuse-guard
cd /opt/pve-abuse-guard

# Copy mã nguồn dự án vào thư mục này (hoặc git clone)
# Cài đặt virtualenv
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

### Bước 3: Cấu Hình Hệ Thống

Copy file cấu hình mẫu:

```bash
cp config.example.yaml config.yaml
nano config.yaml
```

Điền các thông tin quan trọng:

```yaml
proxmox:
  host: "127.0.0.1"
  port: 8006
  user: "abuse-monitor@pam"
  token_name: "pve-guard"
  token_value: "DIEN_TOKEN_SECRET_O_BUOC_1_VAO_DAY"
  verify_ssl: false
  web_ui_url: "https://pve.yourdomain.com:8006" # Link mở giao diện Proxmox

mining_rule:
  cpu_threshold_percent: 90.0 # Ngưỡng CPU %
  duration_minutes: 30        # Số phút liên tục
  poll_interval_seconds: 60   # Quét mỗi 60 giây
  exclude_vmids:              # VMID không bao giờ cảnh báo
    - 9999

discord:
  webhook_url: "https://discord.com/api/webhooks/xxxx/yyyy" # Webhook kênh Discord của bạn
  cooldown_minutes: 60        # Tránh spam lặp lại
  notify_on_resolved: true    # Báo khi VM đã hạ nhiệt
```

---

### Bước 4: Kiểm Tra Hoạt Động (CLI Tools)

Trước khi kích hoạt service chạy ngầm, hãy chạy các lệnh kiểm thử:

**1. Kiểm tra gửi thông báo Discord:**
```bash
/opt/pve-abuse-guard/.venv/bin/python3 -m src.main -c config.yaml --test-webhook
```
*(Nếu thành công, bạn sẽ nhận được một tin nhắn Test màu xanh dương trên kênh Discord).*

**2. Kiểm tra kết nối tới Proxmox API và danh sách VM:**
```bash
/opt/pve-abuse-guard/.venv/bin/python3 -m src.main -c config.yaml --test-pve
```
*(Lệnh sẽ in ra phiên bản Proxmox và toàn bộ danh sách VM/CT kèm mức CPU hiện tại).*

**3. Chạy thử nghiệm 1 chu kỳ kiểm tra thực tế:**
```bash
/opt/pve-abuse-guard/.venv/bin/python3 -m src.main -c config.yaml --once
```

**4. Chạy mô phỏng Debug toàn bộ quy trình (không cần chờ 30 phút thật):**
```bash
/opt/pve-abuse-guard/.venv/bin/python3 -m src.main --debug-sim
```
*(Lệnh này sẽ tạo luồng dữ liệu ảo giả lập VM bình thường -> Bắt đầu đào coin -> Đạt ngưỡng 30 phút -> Bắn cảnh báo -> Bật Cooldown -> Hạ nhiệt -> Bắn Resolved).*

---

### Bước 5: Cài Đặt Chạy Dưới Dạng Systemd Service

Để hệ thống tự động khởi chạy cùng Proxmox và tự phục hồi khi có sự cố:

```bash
# 1. Copy file service vào thư mục systemd
cp pve-abuse-guard.service /etc/systemd/system/pve-abuse-guard.service

# 2. Reload daemon và bật service
systemctl daemon-reload
systemctl enable --now pve-abuse-guard.service

# 3. Kiểm tra trạng thái
systemctl status pve-abuse-guard.service
```

Xem log hoạt động theo thời gian thực:
```bash
journalctl -u pve-abuse-guard.service -f
```

---

## 📊 Mô Phỏng Cảnh Báo Discord

### 🚨 Cảnh Báo Vi Phạm (Violation Embed)
```text
🚨 [CRITICAL] Phát hiện nghi vấn đào tiền ảo trên VM 105
Máy ảo ubuntu-cloud-01 (VMID: 105) đang duy trì mức CPU cực cao liên tục trong thời gian dài.

🖥️ Máy ảo (VM): ubuntu-cloud-01 (ID: 105)      🌐 Node Proxmox: pve-node-01
⚡ CPU Hiện tại: 99.4%                         📊 Thống kê CPU: TB 98.6% (Đỉnh: 100%)
⏱️ Thời gian vi phạm: 32 phút 10 giây           💾 RAM / Uptime: 3.8 GB / 4.0 GB | 14d 6h
🔗 Proxmox Web UI: [Bấm vào đây để mở VM trên Proxmox Web UI](https://pve.../#v1:0:=qemu/105)
```

### ✅ Cảnh Báo Hồi Phục (Resolved Embed)
```text
✅ [ĐÃ HẾT VI PHẠM] VM 105 (ubuntu-cloud-01) đã hạ nhiệt
Chỉ số CPU của máy ảo ubuntu-cloud-01 (VMID: 105) đã hạ xuống mức bình thường (8.2%).
Trạng thái cảnh báo đã được giải phóng.
```

---

## 🧪 Kiểm Thử Tự Động (Unit Tests)

Dự án đi kèm bộ unit tests bao phủ 100% logic:
- Cơ chế In-Memory Ring Buffer & Eviction.
- Thuật toán Sliding Window tính thời gian CPU liên tục.
- Cooldown & chặn cảnh báo trùng lặp.
- Phát hiện hạ nhiệt (Resolved).
- Xử lý Rate-limit Discord 429 và thử lại.
- Can thiệp tự động ở chế độ Dry-run và Whitelist.

Chạy test:
```bash
source .venv/bin/activate
pytest -v
```

---

## ⚙️ Triển Khai Qua Docker (Tùy Chọn)

Nếu bạn muốn chạy qua Docker thay vì Systemd:

```bash
# Khởi chạy bằng docker-compose
docker compose up -d

# Xem log
docker compose logs -f
```

---

## 🔒 Bản Quyền & Giấy Phép
Phát hành theo giấy phép **MIT License**. Tự do sử dụng cho mục đích cá nhân và thương mại.
