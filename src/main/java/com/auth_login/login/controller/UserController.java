package com.auth_login.login.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/user")
public class UserController {

  @GetMapping("/me")
  @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
  public String me() {
    return "Hello, authenticated USER/ADMIN!";
  }
}
