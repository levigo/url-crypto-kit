package com.neverpile.urlcrypto;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class ExpiredException extends AuthenticationException {
  private static final long serialVersionUID = 1L;

  public ExpiredException(final String msg) {
    super(msg);
  }
}
