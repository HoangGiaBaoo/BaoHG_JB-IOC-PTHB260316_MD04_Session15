# md04_ss15 – JWT Microservices (Identity / Gateway / Course)

| Service | Port | Vai trò |
|---|---|---|
| gateway-service | 8080 | Verify JWT, check Redis blacklist, gắn header `X-User-*` |
| identity-service | 8081 | Login / Refresh (rotation) / Logout, PostgreSQL + Redis |
| course-service | 8082 | Phân quyền `@PreAuthorize` dựa trên header từ Gateway |

## Chạy
1. PostgreSQL: db `postgres`, user `postgres` / `Giabao2005@` (bảng tự tạo bằng `ddl-auto=update`).
2. Redis: `docker compose up -d`
3. Chạy 3 service (IDE hoặc `./mvnw -pl identity-service spring-boot:run`, tương tự cho 2 service còn lại).

Tài khoản mẫu (mật khẩu `123456`):

| username | role | permissions |
|---|---|---|
| instructor | INSTRUCTOR | COURSE_READ, COURSE_WRITE |
| student | STUDENT | COURSE_READ |
| reader | STUDENT | COURSE_READ |

## Test
Import `postman/md04_ss15.postman_collection.json`, đổi biến `username` rồi chạy lần lượt các request. Mọi request đều đi qua Gateway `:8080`.

- Bài 1: Login → dán `accessToken` vào jwt.io thấy `sub`, `role`, `permissions`, `jti`; bảng `refresh_tokens` có dữ liệu.
- Bài 2: GET `/api/courses` không token / token sai → 401.
- Bài 3 + 6: `student`/`reader` gọi POST `/api/courses` → 403; `instructor` → 201.
- Bài 4: Refresh → cặp token mới; refresh lại token cũ → 403.
- Bài 5: Logout → gọi lại GET `/api/courses` bằng token cũ → 401 (`jti` nằm trong Redis `blacklist:<jti>` với TTL = thời gian sống còn lại).
