package com.auth_login.login.dto;

public record AuthResponse(String token, String tokenType, long expiresInSeconds) {}
