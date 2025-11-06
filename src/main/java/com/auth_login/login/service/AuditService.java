package com.auth_login.login.service;

import com.auth_login.login.entity.AuditLog;
import com.auth_login.login.repo.AuditLogRepository;
import org.springframework.stereotype.Service;

@Service
public class AuditService {
  private final AuditLogRepository repo;

  public AuditService(AuditLogRepository repo) {
    this.repo = repo;
  }

  public void log(Long userId, String username, AuditLog.Action action, String ip) {
    AuditLog log = new AuditLog();
    log.setUserId(userId);
    log.setUsername(username);
    log.setAction(action);
    log.setIpAddress(ip);
    repo.save(log);
  }
}
