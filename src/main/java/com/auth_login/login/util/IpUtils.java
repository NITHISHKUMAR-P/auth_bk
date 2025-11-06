package com.auth_login.login.util;

import jakarta.servlet.http.HttpServletRequest;

public class IpUtils {
  public static String clientIp(HttpServletRequest request) {
    String[] headers = {
        "X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP", "X-Client-IP",
        "X-Forwarded", "Forwarded-For", "Forwarded"
    };
    for (String h : headers) {
      String v = request.getHeader(h);
      if (v != null && !v.isBlank()) return v.split(",")[0].trim();
    }
    return request.getRemoteAddr();
  }
}
