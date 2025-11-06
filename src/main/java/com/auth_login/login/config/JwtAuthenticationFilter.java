package com.auth_login.login.config;

import com.auth_login.login.entity.UserAccount;
import com.auth_login.login.repo.UserAccountRepository;
import com.auth_login.login.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.stream.Collectors;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private final JwtService jwtService;
  private final UserAccountRepository userRepo;

  public JwtAuthenticationFilter(JwtService jwtService, UserAccountRepository userRepo) {
    this.jwtService = jwtService;
    this.userRepo = userRepo;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain filterChain) throws ServletException, IOException {

    String auth = request.getHeader(HttpHeaders.AUTHORIZATION);

    if (StringUtils.hasText(auth) && auth.startsWith("Bearer ")) {
      String token = auth.substring(7);
      try {
        String username = jwtService.parse(token).getBody().getSubject();
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
          UserAccount user = userRepo.findByUsername(username).orElse(null);
          if (user != null && user.isEnabled() && !jwtService.isExpired(token)) {
            var authorities = user.getRoles().stream()
                .map(r -> new SimpleGrantedAuthority(r.name()))
                .collect(Collectors.toList());

            var principal = new org.springframework.security.core.userdetails.User(
                username, "", authorities
            );
            var authToken = new UsernamePasswordAuthenticationToken(principal, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authToken);
          }
        }
      } catch (Exception ignored) { }
    }

    filterChain.doFilter(request, response);
  }
}
