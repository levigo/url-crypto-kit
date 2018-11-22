package com.neverpile.urlcrypto;

import java.time.ZonedDateTime;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;

public class PreSignedRequest {
  private final ZonedDateTime expiryTime;
  
  private final String username;
  
  private final String signature;
  
  private final List<GrantedAuthority> authorities;
  
  public PreSignedRequest(final ZonedDateTime expiryTime, final String username, final String signature,
      final List<GrantedAuthority> authorities) {
    super();
    this.expiryTime = expiryTime;
    this.username = username;
    this.signature = signature;
    this.authorities = authorities;
  }

  public ZonedDateTime getExpiryTime() {
    return expiryTime;
  }

  public String getUsername() {
    return username;
  }

  public String getSignature() {
    return signature;
  }

  public List<GrantedAuthority> getAuthorities() {
    return authorities;
  }
}