package com.auth_login.login.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

  @GetMapping("/dashboard")
  @PreAuthorize("hasRole('ADMIN')")
  public String dashboard() {
    return "Hello ADMIN, secure dashboard!";
  }
}
