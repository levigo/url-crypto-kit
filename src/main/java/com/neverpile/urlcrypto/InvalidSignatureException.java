package com.neverpile.urlcrypto;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class InvalidSignatureException extends AuthenticationException {
  private static final long serialVersionUID = 1L;

  public InvalidSignatureException(final String msg) {
    super(msg);
  }
}
