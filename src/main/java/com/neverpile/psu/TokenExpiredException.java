package com.neverpile.psu;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class TokenExpiredException extends AuthenticationException {
  private static final long serialVersionUID = 1L;

  public TokenExpiredException(final String msg) {
    super(msg);
  }
}
