# Auth User Service

Auth User Service là service quản lý định danh và tài khoản người dùng cho hệ thống ecommerce. Service chịu trách nhiệm cho đăng ký, đăng nhập, JWT/refresh token, xác thực email/phone, reset password, MFA, hồ sơ người dùng, RBAC, seller onboarding và phát domain events qua outbox/Kafka.

## Tổng quan

Service chạy bằng Spring Boot và dùng các thành phần chính:

| Thành phần | Vai trò |
| --- | --- |
| Java 25 | Runtime/build Java chính của project |
| Spring Boot | Web API, security, JPA, actuator |
| MySQL 8.4 | Lưu users, tokens, RBAC, outbox, shop/onboarding |
| Redis 7.4 | Cache/security state |
| Kafka 3.9 | Event bus local |
| Outbox pattern | Ghi event vào DB trước, scheduler publish sang Kafka |
| Docker Compose | Chạy full local stack |

Base URL mặc định khi chạy local:

```text
http://localhost:8081
```

## Yêu cầu

- Docker Desktop
- Docker Compose v2
- Java 25 nếu muốn chạy Maven trực tiếp ngoài Docker
- Maven Wrapper có sẵn trong repo
- PowerShell trên Windows, hoặc shell tương đương trên macOS/Linux

## Cấu trúc quan trọng

```text
.
|-- Dockerfile
|-- docker-compose.yml
|-- .env.example
|-- docker/kafka/
|   |-- create-topics.sh
|   |-- smoke-test.sh
|   `-- outbox-e2e-smoke-test.sh
|-- src/main/resources/
|   |-- application.yaml
|   |-- application-local.yaml
|   `-- db/migration/
`-- docs/contracts/
```

## Cấu hình `.env`

Repo có sẵn file mẫu:

```text
.env.example
```

Tạo file `.env` từ file mẫu:

PowerShell:

```powershell
Copy-Item .env.example .env
```

Bash:

```bash
cp .env.example .env
```

Sau đó sửa các giá trị placeholder trong `.env`, đặc biệt là các khóa mã hóa/JWT.

### Biến quan trọng

| Biến | Ý nghĩa |
| --- | --- |
| `MYSQL_DATABASE` | Tên database local |
| `MYSQL_USER` / `MYSQL_PASSWORD` | User/password MySQL |
| `MYSQL_ROOT_PASSWORD` | Root password MySQL container |
| `AUTH_PUBLIC_BASE_URL` | URL frontend dùng trong email links |
| `AUTH_EMAIL_VERIFICATION_TTL_MINUTES` | Thời hạn email verification token, mặc định 30 phút |
| `AUTH_OUTBOX_ENCRYPTION_KEY_BASE64` | Khóa mã hóa payload outbox |
| `AUTH_AUDIT_HASH_KEY_BASE64` | Khóa hash audit metadata |
| `AUTH_OTP_HASH_KEY_BASE64` | Khóa hash OTP |
| `AUTH_MFA_ENCRYPTION_KEY_BASE64` | Khóa mã hóa MFA secret |
| `AUTH_JWT_PRIVATE_KEY_BASE64` | RSA private key dạng DER base64 |
| `AUTH_JWT_PUBLIC_KEY_BASE64` | RSA public key dạng DER base64 |

### Tạo khóa local

Tạo khóa 32-byte base64 bằng PowerShell:

```powershell
[Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
```

Dùng giá trị sinh ra cho:

```text
AUTH_OUTBOX_ENCRYPTION_KEY_BASE64
AUTH_AUDIT_HASH_KEY_BASE64
AUTH_OTP_HASH_KEY_BASE64
AUTH_MFA_ENCRYPTION_KEY_BASE64
```

JWT key cần là RSA key pair. Nếu có OpenSSL:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt-private.pem
openssl pkcs8 -topk8 -nocrypt -in jwt-private.pem -outform DER | openssl base64 -A
openssl rsa -pubout -in jwt-private.pem -outform DER | openssl base64 -A
```

Gắn output dòng thứ hai cho `AUTH_JWT_PRIVATE_KEY_BASE64`.

Gắn output dòng thứ ba cho `AUTH_JWT_PUBLIC_KEY_BASE64`.

Không commit file `.env`, `.pem`, `.key`, `.crt`.

## Chạy local bằng Docker Compose

Build và start toàn bộ stack:

```powershell
docker compose up --build
```

Chạy nền:

```powershell
docker compose up -d --build
```

Xem log service:

```powershell
docker compose logs -f user-service
```

Dừng stack:

```powershell
docker compose down
```

Dừng và xóa volume local:

```powershell
docker compose down -v
```

Lưu ý: `down -v` sẽ xóa dữ liệu MySQL/Redis/Kafka local.

## Kafka topics

Compose có service `kafka-init` để tạo topics cần thiết.

Chạy riêng Kafka init:

```powershell
docker compose up kafka-init
```

Log thành công cần có:

```text
All Kafka topics are ready.
```

Các script trong `docker/kafka/*.sh` phải dùng line ending LF. Repo đã cấu hình `.gitattributes` để tránh lỗi CRLF trên Windows.

## Health check

Readiness endpoint nên dùng cho Docker/Kubernetes:

```text
GET http://localhost:8081/actuator/health/readiness
```

Kết quả tốt:

```json
{
  "status": "UP"
}
```

Liveness endpoint:

```text
GET http://localhost:8081/actuator/health/liveness
```

Health tổng:

```text
GET http://localhost:8081/actuator/health
```

Lưu ý: `/actuator/health` tổng có thể `DOWN` nếu `outboxLag` phát hiện outbox event bị failed hoặc pending quá ngưỡng. Khi đó service chưa chắc đã chết; hãy kiểm tra readiness/liveness và bảng outbox trong database.

## API cơ bản

Các endpoint dưới đây dùng prefix:

```text
/api/v1/auth
```

### Signup

```http
POST /api/v1/auth/signup
Content-Type: application/json
```

Ví dụ body:

```json
{
  "email": "dev@example.com",
  "password": "Password@123",
  "fullName": "Dev User"
}
```

Sau khi signup, service tạo email verification token, lưu hash token vào DB và phát command gửi email qua outbox/Kafka.

### Signin

```http
POST /api/v1/auth/signin
Content-Type: application/json
```

Ví dụ body:

```json
{
  "email": "dev@example.com",
  "password": "Password@123"
}
```

### Google Sign-In

```http
POST /api/v1/auth/google
Content-Type: application/json
```

Body nhận Google ID token từ frontend:

```json
{
  "id_token": "<google-id-token>"
}
```

Service xác minh ID token với Google, sau đó trả access/refresh token nội bộ.
Google user mới được tạo buyer account; Google user đã tồn tại sẽ đăng nhập.
Xem chi tiết về lỗi và liên kết tài khoản email/mật khẩu tại
[`docs/google-signin-contract.md`](docs/google-signin-contract.md).

### Refresh token

```http
POST /api/v1/auth/refresh
Content-Type: application/json
```

## Email verification flow

Flow hiện tại:

1. User signup.
2. Service tạo raw verification token.
3. Service chỉ lưu hash của token vào database.
4. Raw token được đưa vào link email dạng:

   ```text
   {AUTH_PUBLIC_BASE_URL}{AUTH_EMAIL_VERIFICATION_PATH}?t={raw-token}
   ```

5. Frontend nhận token từ query `t`.
6. Frontend gọi API verify của auth service.
7. Backend hash token nhận được và so khớp với hash trong database.

Ví dụ local:

```text
AUTH_PUBLIC_BASE_URL=http://localhost:3000
AUTH_EMAIL_VERIFICATION_PATH=/verify
AUTH_EMAIL_VERIFICATION_TTL_MINUTES=30
```

Khi đó link email local sẽ có dạng:

```text
http://localhost:3000/verify?t=<raw-verification-token>
```

### Vì sao link trỏ về frontend?

Email link nên trỏ về frontend, không trỏ trực tiếp backend, vì frontend cần hiển thị trang xác thực, loading, lỗi token hết hạn, nút gửi lại email, rồi gọi backend verify API.

Khi chưa host domain thật, đặt:

```text
AUTH_PUBLIC_BASE_URL=http://localhost:3000
```

Khi lên môi trường thật, đổi sang domain frontend:

```text
AUTH_PUBLIC_BASE_URL=https://taca.vn
```

### Raw token trong URL có an toàn không?

Cách này chấp nhận được nếu token:

- đủ dài và random;
- chỉ dùng một lần;
- hết hạn nhanh, hiện tại 30 phút;
- trong DB chỉ lưu hash, không lưu raw token;
- chỉ gửi qua HTTPS trên môi trường thật;
- không log full URL/token ở frontend, backend, reverse proxy hoặc analytics.

Không đưa verification token vào fragment `#...` nếu backend cần nhận token từ frontend API call bình thường. Query `?t=...` là lựa chọn phổ biến cho email verification.

## Outbox và Kafka

Service dùng outbox pattern để tránh mất event:

1. Business transaction ghi dữ liệu chính.
2. Cùng transaction ghi outbox event.
3. Scheduler đọc outbox event chưa publish.
4. Publish sang Kafka.
5. Cập nhật trạng thái published/failed.

Các cấu hình local quan trọng:

```text
AUTH_OUTBOX_PUBLISHER_ENABLED=true
AUTH_OUTBOX_POLL_INTERVAL=PT5S
AUTH_OUTBOX_BATCH_SIZE=50
AUTH_OUTBOX_MAX_ATTEMPTS=3
AUTH_OUTBOX_TOPIC_USER_EVENTS=user.events
AUTH_OUTBOX_TOPIC_NOTIFICATION_COMMANDS=notification.commands
```

Nếu `/actuator/health` tổng bị `DOWN` do `outboxLag`, kiểm tra bảng outbox để xem event nào failed/pending.

## Smoke tests

Chạy Kafka smoke test:

```powershell
docker compose --profile smoke run --rm kafka-smoke
```

Chạy outbox E2E smoke test:

```powershell
docker compose --profile smoke run --rm outbox-e2e-smoke
```

## Chạy test bằng Maven

Chạy toàn bộ test:

```powershell
.\mvnw.cmd test
```

Nếu Maven Wrapper trên máy local gặp lỗi, có thể dùng Maven cài sẵn:

```powershell
mvn test
```

Chạy một nhóm test liên quan email verification/outbox:

```powershell
mvn "-Dtest=SignupIntegrationTest,EmailVerificationResendIntegrationTest,EmailVerificationIntegrationTest,NotificationCommandEnvelopeTest,NotificationCommandEnvelopeSchemaContractTest,OutboxPublisherServiceTest" test
```

## Build Docker image bằng Dockerfile

Project có sẵn `Dockerfile` ở thư mục gốc repo. Developer khác có thể dùng file này để build image local, chạy thử container, sau đó tag và push image lên DockerHub.

### Build image local

Chạy lệnh sau tại thư mục gốc project:

```powershell
docker build -t auth-user-service:local .
```

Kiểm tra image vừa build:

```powershell
docker images auth-user-service
```

Dockerfile hiện tại dùng multi-stage build:

- Stage build dùng Java 25 JDK để build jar.
- Stage runtime dùng Java 25 JRE để chạy nhẹ hơn.
- App chạy bằng user non-root.
- Healthcheck dùng readiness endpoint.
- `JAVA_TOOL_OPTIONS` có cấu hình JVM phù hợp container.

### Chạy thử image vừa build

Thông thường service cần MySQL, Redis, Kafka và các biến môi trường trong `.env`, nên cách dễ nhất để chạy local vẫn là Docker Compose:

```powershell
docker compose up -d --build
```

Nếu chỉ muốn kiểm tra image có thể start được, bạn có thể chạy container thủ công, nhưng cần truyền đủ env và đảm bảo các service phụ thuộc có thể truy cập được:

```powershell
docker run --rm --name auth-user-service -p 8081:8081 --env-file .env auth-user-service:local
```

Lưu ý: lệnh `docker run` ở trên chỉ phù hợp khi `.env` trỏ đến database/cache/broker có thể truy cập được từ container. Với local development, Docker Compose vẫn là lựa chọn khuyến nghị.

### Tag image để push lên DockerHub

DockerHub image thường có dạng:

```text
<dockerhub-username>/<repository-name>:<tag>
```

Ví dụ:

```text
duynhat/auth-user-service:1.0.0
duynhat/auth-user-service:latest
```

Tag image local:

```powershell
docker tag auth-user-service:local <dockerhub-username>/auth-user-service:1.0.0
docker tag auth-user-service:local <dockerhub-username>/auth-user-service:latest
```

Thay `<dockerhub-username>` bằng username DockerHub thật.

### Đăng nhập DockerHub

```powershell
docker login
```

Nhập DockerHub username và access token/password khi Docker CLI yêu cầu.

Khuyến nghị dùng DockerHub access token thay vì password tài khoản chính.

### Push image lên DockerHub

```powershell
docker push <dockerhub-username>/auth-user-service:1.0.0
docker push <dockerhub-username>/auth-user-service:latest
```

Sau khi push thành công, developer khác có thể pull image:

```powershell
docker pull <dockerhub-username>/auth-user-service:1.0.0
```

## Troubleshooting

### `kafka-init` exit 2

Nguyên nhân thường gặp trên Windows là script `.sh` bị CRLF. Repo đã cấu hình:

```text
*.sh text eol=lf
```

Nếu vẫn lỗi, kiểm tra line ending:

```powershell
git ls-files --eol docker/kafka
```

Kết quả mong muốn là `w/lf`.

### `/actuator/health` là `DOWN`

Kiểm tra readiness trước:

```text
http://localhost:8081/actuator/health/readiness
```

Nếu readiness `UP` nhưng health tổng `DOWN`, nhiều khả năng custom health indicator như `outboxLag` đang báo lỗi do event failed/pending.

Với local dev, có thể reset dữ liệu bằng:

```powershell
docker compose down -v
docker compose up -d --build
```

Chỉ dùng cách này khi chấp nhận mất dữ liệu local.

### Email link mở ra `Not found`

Kiểm tra `AUTH_PUBLIC_BASE_URL`.

Nếu frontend local chạy port 3000:

```text
AUTH_PUBLIC_BASE_URL=http://localhost:3000
```

Nếu frontend production dùng domain thật:

```text
AUTH_PUBLIC_BASE_URL=https://taca.vn
```

Đảm bảo frontend có route:

```text
/verify
```

Route này đọc query `t`, sau đó gọi backend verify API.

### Token xác thực email hết hạn

TTL hiện tại được cấu hình bằng:

```text
AUTH_EMAIL_VERIFICATION_TTL_MINUTES=30
```

Nếu token hết hạn, frontend nên hiển thị thông báo rõ ràng và cho phép user gửi lại email xác thực.

## Ghi chú cho developer

- Không commit `.env` hoặc secret thật.
- Khi thêm env mới vào application config, cập nhật cả `.env.example` và `docker-compose.yml` nếu service container cần đọc biến đó.
- Khi thêm Kafka topic mới, cập nhật script trong `docker/kafka/create-topics.sh`.
- Khi thay đổi event schema, cập nhật contract trong `docs/contracts/` và test tương ứng.
- Với local, `AUTH_PUBLIC_BASE_URL=http://localhost:3000` là hợp lý nếu frontend chạy local.
- Với staging/production, luôn dùng HTTPS cho public base URL.
