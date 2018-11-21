package com.neverpile.psu.springsecurity;

import static java.time.Duration.*;

import java.time.Duration;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import com.neverpile.psu.PreSignedUrlCryptoKit;
import com.neverpile.psu.PreSignedUrlEnabled;

public class GeneratePreSignedUrlInterceptor implements HandlerInterceptor {

  @Autowired
  private PreSignedUrlCryptoKit crypto;

  /**
   * This Method execute before the execution of the target resource. If the request contains the
   * parameter "X-NPE-PSU duration" and the target resource the annotation "PSUEnabled" the method
   * creates a Pre Sign Url.
   *
   * @return Returns true if the method does not create a Pre Sign Url.
   */
  @Override
  public boolean preHandle(final HttpServletRequest request, final HttpServletResponse response, final Object handler)
      throws Exception {
    String requestedExpiryTime = request.getParameter(PreSignedUrlCryptoKit.DURATION);
    if (null != requestedExpiryTime) {
      if (handler instanceof HandlerMethod) {
        PreSignedUrlEnabled psuEnabled = ((HandlerMethod) handler).getMethodAnnotation(PreSignedUrlEnabled.class);
        if (null == psuEnabled) {
          throw new AuthenticationException("Pre Sign URLs(PSU) not activated for this method") {
            private static final long serialVersionUID = 1L;
          };
        } else {
          Duration expiryTime = parse(requestedExpiryTime);
          
          String url = crypto.generatePreSignedUrl(expiryTime, request.getRequestURL().toString());

          response.setContentType("text/uri-list");
          response.getWriter().write(url + "\r\n");
          return false;
        }
      }
    }
    return true;
  }
}
