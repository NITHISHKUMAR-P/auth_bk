# Database Details
## User Table:
<img width="1546" height="156" alt="image" src="https://github.com/user-attachments/assets/864294bc-fc27-4b55-8322-a1c7d3d6bbc5" />
```sql
CREATE TABLE users (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(255) UNIQUE NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL, //BCrypt-hashed password
  enabled BOOLEAN NOT NULL,
  failed_attempts INT NOT NULL,
  locked_until DATETIME NULL,
  created_at DATETIME,
  updated_at DATETIME
);
```
Initially failed attempt will be zero after wrong password, failed_attempt will increment by 1,
After 3 failures we set locked_until = now + 5 minutes.
On successful login we reset failed_attempts = 0 + clear lock.
# Roles Table:
<img width="322" height="202" alt="image" src="https://github.com/user-attachments/assets/91b73f9a-3391-4bf8-b7d1-f8cf705d9c74" />
```java
@ElementCollection(fetch = FetchType.EAGER)
@Enumerated(EnumType.STRING)
@CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
@Column(name = "role")
private Set<Role> roles;
```
This generates a separate table that stores 1 row per user
```sql
CREATE TABLE user_roles (
  user_id BIGINT NOT NULL,
  role VARCHAR(255) NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
```
In userDetailService, authorities = ["ROLE_USER", "ROLE_ADMIN"] is matched with .requestMatchers("/api/admin/**").hasRole("ADMIN")

## Audit Table:
<img width="815" height="446" alt="image" src="https://github.com/user-attachments/assets/b81b9000-e319-47af-9908-a708dd4ff31c" />
```sql
CREATE TABLE audit_logs (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT,
  username VARCHAR(255),
  action VARCHAR(50),     -- LOGIN_SUCCESS / LOGIN_FAILURE / LOGOUT
  ip_address VARCHAR(255),
  at DATETIME
);
```
It is recorded for successful login, failed login and logout.

