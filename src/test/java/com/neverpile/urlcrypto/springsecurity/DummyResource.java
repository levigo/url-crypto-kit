package com.neverpile.urlcrypto.springsecurity;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.neverpile.urlcrypto.PreSignedUrlEnabled;

@RestController
public class DummyResource {
  @GetMapping("foo")
  @PreSignedUrlEnabled
  public String foo() {
    return "foo";
  }
  
  @GetMapping("bar")
  @PreSignedUrlEnabled
  public String bar(final Authentication auth) {
    return auth.getName() + "/" + auth.getAuthorities();
  }

  @GetMapping("baz")
  public String baz() {
    return "baz";
  }
}
