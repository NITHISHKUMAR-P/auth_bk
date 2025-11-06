package com.auth_login.login.service;

import com.auth_login.login.entity.Role;
import com.auth_login.login.entity.UserAccount;
import com.auth_login.login.repo.UserAccountRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Set;

@Service
public class UserService {

  private final UserAccountRepository userRepo;
  private final PasswordEncoder encoder;

  public UserService(UserAccountRepository userRepo, PasswordEncoder encoder) {
    this.userRepo = userRepo;
    this.encoder = encoder;
  }

  public UserAccount register(String username, String email, String rawPassword, String roleStr) {
    if (userRepo.existsByUsername(username)) throw new IllegalArgumentException("Username taken");
    if (userRepo.existsByEmail(email)) throw new IllegalArgumentException("Email in use");

    Role role = ("ADMIN".equalsIgnoreCase(roleStr)) ? Role.ROLE_ADMIN : Role.ROLE_USER;

    UserAccount user = new UserAccount();
    user.setUsername(username);
    user.setEmail(email);
    user.setPassword(encoder.encode(rawPassword));
    user.setRoles(Set.of(role));
    user.setEnabled(true);
    user.setFailedAttempts(0);
    user.setLockedUntil(null);
    return userRepo.save(user);
  }

  public void recordFailedAttempt(UserAccount user, int threshold, int lockMinutes) {
    int attempts = user.getFailedAttempts() + 1;
    user.setFailedAttempts(attempts);
    if (attempts >= threshold) {
      user.setLockedUntil(Instant.now().plusSeconds(lockMinutes * 60L));
      user.setFailedAttempts(0);
    }
    userRepo.save(user);
  }

  public void recordSuccess(UserAccount user) {
    user.setFailedAttempts(0);
    user.setLockedUntil(null);
    userRepo.save(user);
  }
}
