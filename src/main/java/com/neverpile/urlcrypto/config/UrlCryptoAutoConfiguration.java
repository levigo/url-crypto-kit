package com.neverpile.urlcrypto.config;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;

import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.neverpile.urlcrypto.UrlCryptoKit;
import com.neverpile.urlcrypto.impl.SharedSecretCryptoKit;
import com.neverpile.urlcrypto.springsecurity.GeneratePreSignedUrlInterceptor;
import com.neverpile.urlcrypto.springsecurity.ValidatePreSignedUrlFilter;

/**
 * The PreSignedUrlSupportConfiguration class manages the PSUInterceptors. New interpreters must be
 * registered here. The creation of Pre Sign URLs can be enabled or disabled by setting the
 * "neverpile-eureka.pre-signed-urls.enabled" variable in the properties.
 */
@Configuration
@Import(UrlCryptoConfiguration.class)
public class UrlCryptoAutoConfiguration {
  private final UrlCryptoConfiguration config;

  private final ApplicationContext context;

  public UrlCryptoAutoConfiguration(UrlCryptoConfiguration config, ApplicationContext context) {
    this.config = config;
    this.context = context;
  }

  @Bean
  @ConditionalOnProperty(name = "neverpile.url-crypto.shared-secret.enabled", havingValue = "true",
      matchIfMissing = false)
  SharedSecretCryptoKit sharedSecretCryptoKit() {
    return new SharedSecretCryptoKit();
  }


  static class PSURequestedMatcher implements RequestMatcher {
    @Override
    public boolean matches(final HttpServletRequest request) {
      return null != request.getParameter(UrlCryptoKit.SIGNATURE)
          // don't match requests to the error handler!
          && null == request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
    }
  }

  @Bean
  @Order(4)
  @ConditionalOnBean(UrlCryptoKit.class)
  @ConditionalOnWebApplication
  SecurityFilterChain psuFilterChain(HttpSecurity http) throws Exception {
    ValidatePreSignedUrlFilter psuFilter = new ValidatePreSignedUrlFilter();
    psuFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));

    context.getAutowireCapableBeanFactory().autowireBean(psuFilter);

    // @formatter:off
    http
      .requestMatcher(new PSURequestedMatcher())
      .addFilterBefore(psuFilter, BasicAuthenticationFilter.class)
      .authorizeRequests()
        .antMatchers(HttpMethod.OPTIONS).permitAll()
        .anyRequest().authenticated()
    ;
    // @formatter:on
    return http.build();
  }

  @Bean
  @ConditionalOnBean(UrlCryptoKit.class)
  @ConditionalOnWebApplication
  public GeneratePreSignedUrlInterceptor psuFilter() {
    return new GeneratePreSignedUrlInterceptor();
  }

  @Bean
  @ConditionalOnBean(UrlCryptoKit.class)
  @ConditionalOnWebApplication
  WebMvcConfigurer psuWebMvcConfigurer() {
    return new WebMvcConfigurer() {
      @Override
      public void addInterceptors(final InterceptorRegistry registry) {
        registry.addInterceptor(psuFilter()).addPathPatterns(config.getPathPatterns());
      }
    };
  }
}
