package com.auth_login.login.controller;

import com.auth_login.login.dto.*;
import com.auth_login.login.service.AuthService;
import com.auth_login.login.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

  private final UserService userService;
  private final AuthService authService;

  public AuthController(UserService userService, AuthService authService) {
    this.userService = userService;
    this.authService = authService;
  }

  @PostMapping("/register")
  public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest req) {
    var saved = userService.register(req.username(), req.email(), req.password(), req.role());
    return ResponseEntity.ok("Registered user: " + saved.getUsername());
  }

  @PostMapping("/login")
  public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest req, HttpServletRequest http) {
    return ResponseEntity.ok(authService.login(req.username(), req.password(), http));
  }

  @PostMapping("/logout")
  public ResponseEntity<?> logout(@AuthenticationPrincipal User principal,
                                  @RequestBody(required = false) LogoutRequest body,
                                  HttpServletRequest http) {
    String username = principal != null ? principal.getUsername() : "anonymous";
    authService.logout(username, http);
    return ResponseEntity.ok("Logged out");
  }
}
