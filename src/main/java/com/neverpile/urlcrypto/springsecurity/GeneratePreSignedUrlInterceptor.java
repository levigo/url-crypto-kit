package com.neverpile.urlcrypto.springsecurity;

import static java.time.Duration.*;

import java.lang.annotation.Annotation;
import java.time.Duration;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.server.PathContainer;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import com.neverpile.urlcrypto.UrlCryptoKit;
import com.neverpile.urlcrypto.config.UrlCryptoConfiguration;
import org.springframework.web.servlet.resource.ResourceHttpRequestHandler;
import org.springframework.web.util.pattern.PathPatternParser;

public class GeneratePreSignedUrlInterceptor implements HandlerInterceptor {

  @Autowired
  private UrlCryptoKit crypto;

  @Autowired
  private UrlCryptoConfiguration config;


  /**
   * This Method executes before the execution of the target resource. If the request contains the
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

        Annotation psuEnabled = ((HandlerMethod) handler).getMethodAnnotation(psuEnablingAnnotation);
        if (null == psuEnabled) {
          throw new AuthenticationException("Pre Sign URLs(PSU) not activated for " + handler + ": not annotated with @"
              + psuEnablingAnnotation.getName()) {
            private static final long serialVersionUID = 1L;
          };
        } else {
          return generatePreSignedUrl(request, response, requestedExpiryTime);
        }
      } else if (handler instanceof ResourceHttpRequestHandler) {
        if (isEnabledStaticPath(request)) {
          throw new AuthenticationException("Pre Sign URLs(PSU) not enabled for " + request.getRequestURL().toString()) {
            private static final long serialVersionUID = 1L;
          };
        } else {
          return generatePreSignedUrl(request, response, requestedExpiryTime);
        }
      }
    }
    return true;
  }

  private boolean isEnabledStaticPath(HttpServletRequest request) {
    PathPatternParser ppp = new PathPatternParser();
    return config.getPsuEnabledPathPatterns().stream().noneMatch(
        s -> ppp.parse(s).matches(PathContainer.parsePath(request.getServletPath()))
    );
  }

  private boolean generatePreSignedUrl(HttpServletRequest request, HttpServletResponse response, String requestedExpiryTime)
      throws Exception {
    Duration expiryTime = parse(requestedExpiryTime);

    // limit validity to configured maximum
    if (null != config.getMaxPreSignedValidity() && expiryTime.compareTo(config.getMaxPreSignedValidity()) > 0) {
      expiryTime = config.getMaxPreSignedValidity();
    }

    String url = crypto.generatePreSignedUrl(expiryTime, request.getRequestURL().toString());

    response.setContentType("text/uri-list");
    response.getWriter().write(url + "\r\n");
    return false;
  }
}
