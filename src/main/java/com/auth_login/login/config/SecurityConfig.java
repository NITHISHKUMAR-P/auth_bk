package com.auth_login.login.config;

import com.auth_login.login.repo.UserAccountRepository;
import com.auth_login.login.service.JwtService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.time.Instant;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

  private final UserAccountRepository userRepo;
  private final JwtService jwtService;

  public SecurityConfig(UserAccountRepository userRepo, JwtService jwtService) {
    this.userRepo = userRepo;
    this.jwtService = jwtService;
  }

  @Bean
  public UserDetailsService userDetailsService() {
    return username -> userRepo.findByUsername(username)
        .map(u -> User.withUsername(u.getUsername())
            .password(u.getPassword())
            .accountLocked(u.getLockedUntil() != null && u.getLockedUntil().isAfter(Instant.now()))
            .authorities(u.getRoles().stream().map(Enum::name).toArray(String[]::new))
            .build())
        .orElseThrow(() -> new UsernameNotFoundException("User not found"));
  }

  @Bean
  public PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }

  @Bean
  public DaoAuthenticationProvider daoAuthenticationProvider(UserDetailsService uds, PasswordEncoder pe) {
    var p = new DaoAuthenticationProvider();
    p.setUserDetailsService(uds);
    p.setPasswordEncoder(pe);
    return p;
  }

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration cfg) throws Exception {
    return cfg.getAuthenticationManager();
  }

  private static void writeJson(HttpServletResponse res, int status, String msg) throws IOException {
    res.setStatus(status);
    res.setContentType("application/json");
    res.getWriter().write("{\"message\":\"" + msg.replace("\"","\\\"") + "\"}");
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    var jwtFilter = new JwtAuthenticationFilter(jwtService, userRepo);

    http
      .csrf(csrf -> csrf.disable())
      .cors(Customizer.withDefaults())
      .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
      .authorizeHttpRequests(reg -> reg
          .requestMatchers(HttpMethod.POST, "/api/auth/**").permitAll()
          .requestMatchers(HttpMethod.GET,  "/api/auth/**").permitAll()
          .requestMatchers(HttpMethod.GET, "/health").permitAll()
          .requestMatchers("/error").permitAll()
          .requestMatchers("/api/admin/**").hasRole("ADMIN")
          .anyRequest().authenticated()
      )
      // Return clean JSON instead of 403-at-/error for auth failures
      .exceptionHandling(ex -> ex
          .authenticationEntryPoint((req, res, e) ->
              writeJson(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized"))   // 401
          .accessDeniedHandler((req, res, e) ->
              writeJson(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden"))         // 403
      )
      .formLogin(form -> form.disable())
      .httpBasic(Customizer.withDefaults())
      .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }
}
