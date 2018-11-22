package com.neverpile.urlcrypto.springsecurity;

import static java.time.Duration.*;

import java.lang.annotation.Annotation;
import java.time.Duration;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import com.neverpile.urlcrypto.UrlCryptoKit;
import com.neverpile.urlcrypto.config.UrlCryptoConfiguration;

public class GeneratePreSignedUrlInterceptor implements HandlerInterceptor {

  @Autowired
  private UrlCryptoKit crypto;

  @Autowired
  private UrlCryptoConfiguration config;


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
    String requestedExpiryTime = request.getParameter(UrlCryptoKit.DURATION);
    if (null != requestedExpiryTime) {
      if (handler instanceof HandlerMethod) {
        @SuppressWarnings("unchecked")
        Class<? extends Annotation> psuEnablingAnnotation = (Class<? extends Annotation>) Class.forName(
            config.getEnablePreSignedUrlAnnotationClass());

        Annotation psuEnabled = null != psuEnablingAnnotation
            ? ((HandlerMethod) handler).getMethodAnnotation(psuEnablingAnnotation)
            : null;
        if (null == psuEnabled && null != psuEnablingAnnotation) {
          throw new AuthenticationException("Pre Sign URLs(PSU) not activated for " + handler + ": not annotated with @"
              + psuEnablingAnnotation.getName()) {
            private static final long serialVersionUID = 1L;
          };
        } else {
          Duration expiryTime = parse(requestedExpiryTime);

          // limit validity to configured maximum
          if (null != config.getMaxPreSignedValidity() && expiryTime.compareTo(config.getMaxPreSignedValidity()) > 0)
            expiryTime = config.getMaxPreSignedValidity();

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
