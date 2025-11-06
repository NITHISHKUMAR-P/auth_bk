package com.auth_login.login.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "audit_logs")
public class AuditLog {

  public enum Action {
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    LOGOUT
  }

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  private Long userId;
  private String username;

  @Enumerated(EnumType.STRING)
  private Action action;

  private String ipAddress;
  private Instant at;

  public AuditLog() {}

  public AuditLog(Long id, Long userId, String username, Action action, String ipAddress, Instant at) {
    this.id = id;
    this.userId = userId;
    this.username = username;
    this.action = action;
    this.ipAddress = ipAddress;
    this.at = at;
  }

  @PrePersist
  void prePersist() {
    if (at == null) at = Instant.now();
  }

  // Getters & Setters
  public Long getId() { return id; }
  public void setId(Long id) { this.id = id; }

  public Long getUserId() { return userId; }
  public void setUserId(Long userId) { this.userId = userId; }

  public String getUsername() { return username; }
  public void setUsername(String username) { this.username = username; }

  public Action getAction() { return action; }
  public void setAction(Action action) { this.action = action; }

  public String getIpAddress() { return ipAddress; }
  public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }

  public Instant getAt() { return at; }
  public void setAt(Instant at) { this.at = at; }
}
