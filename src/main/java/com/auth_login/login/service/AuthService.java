package com.auth_login.login.service;

import com.auth_login.login.dto.AuthResponse;
import com.auth_login.login.entity.AuditLog;
import com.auth_login.login.entity.UserAccount;
import com.auth_login.login.repo.UserAccountRepository;
import com.auth_login.login.util.IpUtils;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Service
public class AuthService {

  private final AuthenticationManager authManager;
  private final JwtService jwtService;
  private final UserAccountRepository userRepo;
  private final UserService userService;
  private final AuditService auditService;

  private static final int ATTEMPT_THRESHOLD = 3;
  private static final int LOCK_MINUTES = 5;

  public AuthService(AuthenticationManager authManager, JwtService jwtService,
                     UserAccountRepository userRepo, UserService userService,
                     AuditService auditService) {
    this.authManager = authManager;
    this.jwtService = jwtService;
    this.userRepo = userRepo;
    this.userService = userService;
    this.auditService = auditService;
  }

  public AuthResponse login(String username, String password, HttpServletRequest req) {
    UserAccount user = userRepo.findByUsername(username)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials"));

    if (user.getLockedUntil() != null && user.getLockedUntil().isAfter(Instant.now())) {
      long secondsLeft = user.getLockedUntil().getEpochSecond() - Instant.now().getEpochSecond();
      throw new ResponseStatusException(HttpStatus.LOCKED, "Account locked. Try again in " + secondsLeft + "s");
    }

    try {
      authManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
      userService.recordSuccess(user);

      Map<String, Object> claims = new HashMap<>();
      claims.put("roles", user.getRoles());
      String token = jwtService.generateToken(username, claims);
      auditService.log(user.getId(), user.getUsername(), AuditLog.Action.LOGIN_SUCCESS, IpUtils.clientIp(req));

      long expiresInSeconds = 60L * 60L * 2L; // 120m default
      return new AuthResponse(token, "Bearer", expiresInSeconds);

    } catch (AuthenticationException ex) {
      userService.recordFailedAttempt(user, ATTEMPT_THRESHOLD, LOCK_MINUTES);
      auditService.log(user.getId(), user.getUsername(), AuditLog.Action.LOGIN_FAILURE, IpUtils.clientIp(req));
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
    }
  }

  public void logout(String username, HttpServletRequest req) {
    userRepo.findByUsername(username).ifPresent(u ->
        auditService.log(u.getId(), u.getUsername(), AuditLog.Action.LOGOUT, IpUtils.clientIp(req)));
    // Stateless JWT: audit only. Add blacklist if you need forced invalidation.
  }
}
