# BackdoorGuard

**Công cụ quét bảo mật tĩnh và kiểm toán runtime dành cho quản trị viên máy chủ Minecraft.**

BackdoorGuard kiểm tra JAR plugin để tìm tham chiếu class, lời gọi phương thức, chuỗi nhúng, bất thường của archive và các tổ hợp dấu hiệu hành vi đáng ngờ. Plugin cũng có thể theo dõi thư mục `plugins/` và kiểm toán một số dấu hiệu trên server đang chạy.

> **Trạng thái:** source phiên bản `1.2.0`. Đã chạy kiểm tra tĩnh/smoke test, nhưng **chưa hoàn tất build Maven với Paper API thật và chưa kiểm thử tích hợp đầy đủ trên server**. Xem [VALIDATION.md](VALIDATION.md) trước khi dùng ở môi trường production.

**Tài liệu chi tiết:** xem [Wiki BackdoorGuard](wiki.md) để đọc hướng dẫn cấu hình, lệnh quản trị, cách hiểu kết quả quét, khắc phục sự cố và lưu ý an toàn.


BackdoorGuard là công cụ phát hiện heuristic và kiểm toán, không đảm bảo kết luận một plugin chắc chắn an toàn hoặc độc hại. Plugin chỉ báo cáo phát hiện; không tự xóa, sửa hoặc vô hiệu hóa JAR.

## Các chức năng đã có trong mã nguồn

- **Phân tích JAR/class:** đọc cấu trúc class file JVM, tham chiếu bytecode, lời gọi thành viên, chuỗi được nạp bởi bytecode và tham chiếu `invokedynamic`/bootstrap.
- **Tương quan hành vi:** tính điểm cho các tổ hợp dấu hiệu liên quan tới chạy tiến trình, mạng, truy cập file/biến môi trường, chuỗi liên quan thông tin xác thực, reflection, nạp class động, serialization, JVM agent, chat/OP và endpoint đáng ngờ.
- **Kiểm tra archive:** phát hiện tên entry trùng, đường dẫn bất thường, tỷ lệ nén đáng ngờ, class lỗi, JAR lồng nhau, phần mở rộng không khớp và giới hạn kích thước/độ sâu/số entry.
- **Kiểm tra dữ liệu mã hóa có giới hạn:** có thể giải mã các chuỗi giống Base64 trong giới hạn để tiếp tục phân tích tĩnh; không thực thi dữ liệu giải mã.
- **Kiểm soát hash:** tính SHA-256 và hỗ trợ danh sách hash độc hại, hash tin cậy do admin cung cấp, cùng ngoại lệ giảm trọng số giới hạn theo hash.
- **Quét nền:** dùng worker pool có giới hạn và cache kết quả cho hash JAR sạch đã quét.
- **Theo dõi thư mục:** dùng Java `WatchService` phát hiện JAR mới, bị sửa hoặc bị xóa trong thư mục plugin; file thay đổi được quét sau khoảng chờ/debounce để hạn chế quét khi đang copy.
- **Tín hiệu kiểm toán runtime:** theo dõi thay đổi định danh/main class plugin đã nạp, vị trí code source, một số cờ JVM có khả năng injection/patch, thay đổi command map, danh sách OP và hook bảo vệ của BackdoorGuard.
- **Đa ngôn ngữ:** có tệp riêng cho English, tiếng Việt, Tây Ban Nha, Trung Quốc giản thể, Pháp, Đức, Bồ Đào Nha Brazil, Nga, Nhật và Hàn. Thông báo cho người chơi có thể theo locale của client; khóa dịch thiếu sẽ fallback sang tiếng Anh.
- **Quản trị:** lệnh quét/trạng thái/audit, reload cấu hình, quản lý hash tin cậy, xóa cache, xem điểm vi phạm, tab completion, ghi file log và webhook Discord tùy chọn.

Danh sách này mô tả chức năng trong source, không có nghĩa mọi phát hiện đã được xác thực trên mã độc thực tế hoặc đã thử trên mọi bản server.

## Yêu cầu và tương thích

- JDK **21**
- Maven **3.9+**
- Có kết nối mạng tới Maven repository để tải dependency
- Project hiện khai báo **Paper API 1.21.1** dưới dạng dependency `provided`

Mã nguồn hướng tới hệ sinh thái Paper/Spigot 1.21, nhưng chưa kiểm thử tích hợp trên mọi bản Paper hoặc Spigot. Hãy kiểm tra đúng phiên bản server trên máy staging trước khi dùng production.

## Build từ source

Tại thư mục gốc project, chạy:

```bash
mvn clean package
```

JAR dự kiến:

```text
target/backdoorguard-1.2.0.jar
```

Nếu Maven báo lỗi tải dependency hoặc lỗi API, hãy sửa lỗi đó trước khi triển khai. Repository hiện không kèm JAR dựng sẵn hoặc Maven Wrapper.

## Cài đặt

1. Build project theo hướng dẫn trên.
2. Chép `target/backdoorguard-1.2.0.jar` vào thư mục `plugins/` của server.
3. Khởi động server và kiểm tra console để tìm lỗi lúc nạp.
4. Mở `plugins/BackdoorGuard/config.yml`, xem lại giới hạn quét, ngưỡng cảnh báo, hash tin cậy, webhook và ngôn ngữ.
5. Chạy `/bguard status` và `/bguard scan`, kiểm tra cảnh báo trên server staging trước khi dùng production.

Chọn ngôn ngữ trong `plugins/BackdoorGuard/config.yml`:

```yaml
language: "vi"
```

Mã ngôn ngữ: `en`, `vi`, `es`, `zh_CN`, `fr`, `de`, `pt_BR`, `ru`, `ja`, `ko`.

## Lệnh quản trị

| Lệnh | Chức năng |
|---|---|
| `/bguard status` | Hiển thị trạng thái scanner và watcher. |
| `/bguard scan` | Bắt đầu quét nền thủ công. |
| `/bguard audit` | Kiểm toán danh sách plugin đang nạp và vị trí code source. |
| `/bguard reload` | Tải lại cấu hình và khởi động lại watcher theo cấu hình. |
| `/bguard trust <file.jar>` | Băm JAR nằm trực tiếp trong `plugins/` và thêm hash đó vào danh sách bỏ qua quét tĩnh. **Chỉ dùng sau khi xác minh độc lập.** |
| `/bguard cache clear` | Xóa cache kết quả quét. |
| `/bguard vl <player>` | Xem điểm nghi vấn từ heuristic lệnh của người chơi. |

Quyền quản trị chính là `backdoorguard.admin`. Người nhận cảnh báo dùng `backdoorguard.notify`; `backdoorguard.bypass` bỏ qua heuristic lệnh người chơi và nên chỉ cấp cho tài khoản đáng tin.

## Cấu hình và sử dụng an toàn

- Giảm `jar-scanner.alert-threshold` sẽ tăng độ nhạy nhưng có thể tăng cảnh báo giả.
- `jar-scanner.worker-threads` điều khiển số worker quét song song; đặt phù hợp với tài nguyên máy chủ.
- `known-bad-jar-hashes` nên chứa SHA-256 từ nguồn sự cố đáng tin và đã xác minh độc lập.
- `trusted-jar-hashes` bỏ qua quét tĩnh cho đúng hash đó. File được cập nhật sẽ có hash khác; không tin cậy chỉ dựa vào tên file.
- `known-good-signature-exceptions` có thể giảm một số trọng số chung đối với một SHA-256 cụ thể. Điều này không chứng minh file an toàn; bất thường cấu trúc hoặc tương quan hành vi vẫn có thể cảnh báo.
- `known-plugin-identities` là tùy chọn. Xác minh `name` và `main` từ bản phát hành chính thức trước khi ghim; các bản hợp pháp có thể đổi metadata.
- Giữ bí mật URL/token webhook. Không commit secret đang hoạt động, log chứa dữ liệu riêng tư hoặc JAR production vào repository công khai.
- Sao lưu server và xác minh file đáng ngờ với nhà phát hành chính thức trước khi xử lý. BackdoorGuard không tự xóa hoặc tắt file dựa trên điểm số.

## Trạng thái kiểm thử

Xem [VALIDATION.md](VALIDATION.md) để biết các kiểm tra chi tiết. Smoke test được ghi nhận gồm biên dịch Java với stub Bukkit/Paper tạm thời, phân tích class file mẫu đã biên dịch, kiểm tra class bị hỏng, probe dấu hiệu hành vi và đối chiếu tính nhất quán của 10 tệp ngôn ngữ YAML.

**Chưa xác minh:** `mvn clean package` với Paper API thật, khởi động server Paper/Spigot thực tế, tương thích nhiều phiên bản, hiệu năng tải dài hạn và độ chính xác phát hiện trên bộ dữ liệu mã độc/lành tính đã gán nhãn.

## Giới hạn phát hiện

Bộ phân tích là heuristic tĩnh có giới hạn. Hiện chưa dựng đầy đủ control-flow graph, chưa thực hiện phân tích luồng dữ liệu/taint liên phương thức toàn diện, không mô phỏng hành vi runtime và không thể chứng minh dữ liệu nhạy cảm thực sự đã bị gửi đi. Obfuscation, reflection, payload từ xa, trigger trễ và hành vi phụ thuộc môi trường có thể né quét. Plugin hợp pháp cũng có thể dùng mạng, file I/O, reflection, dữ liệu mã hóa và nạp class động.

Một cảnh báo là **đầu mối cần điều tra**, không phải bằng chứng kết luận. Hãy kiểm tra hash, nhà phát hành, mã nguồn và hành vi liên quan trước khi phân loại plugin là độc hại.

## Giấy phép

Phát hành theo [MIT License](LICENSE). Xem nội dung LICENSE để biết điều khoản áp dụng.
