package com.neverpile.psu;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.neverpile.psu.springsecurity.GeneratePreSignedUrlInterceptor;
import com.neverpile.psu.springsecurity.ValidatePreSignedUrlFilter;

/**
 * The PreSignedUrlSupportConfiguration class manages the PSUInterceptors. New interpreters must be
 * registered here. The creation of Pre Sign URLs can be enabled or disabled by setting the
 * "neverpile-eureka.pre-signed-urls.enabled" variable in the properties.
 */
@Configuration
@ConditionalOnProperty(name = "neverpile-eureka.pre-signed-urls.enabled", havingValue = "true", matchIfMissing = false)
@ComponentScan
public class PreSignedUrlSupportConfiguration {
  @Value("${neverpile-eureka.pre-signed-urls.patterns:/**}")
  private final String[] pathPatterns = new String[]{
      "/**"
  };

  @Order(4)
  private final class WebSecurityConfigurerAdapterExtension extends WebSecurityConfigurerAdapter {
    class PSURequestedMatcher implements RequestMatcher {
      @Override
      public boolean matches(final HttpServletRequest request) {
        return null != request.getParameter(PreSignedUrlCryptoKit.SIGNATURE)
            // don't match requests to the error handler!
            && null == request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
      }
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
      ValidatePreSignedUrlFilter psuFilter = new ValidatePreSignedUrlFilter();
      psuFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));

      getApplicationContext().getAutowireCapableBeanFactory().autowireBean(psuFilter);

      // @formatter:off
      http
        .requestMatcher(new PSURequestedMatcher())
        .addFilterBefore(psuFilter, BasicAuthenticationFilter.class)
        .authorizeRequests()
          .antMatchers(HttpMethod.OPTIONS).permitAll()
          .anyRequest().authenticated()
      ;
      // @formatter:on
    }
  }

  @Bean
  public GeneratePreSignedUrlInterceptor psuFilter() {
    return new GeneratePreSignedUrlInterceptor();
  }

  @Bean
  WebMvcConfigurer psuWebMvcConfigurer() {
    return new WebMvcConfigurer() {
      @Override
      public void addInterceptors(final InterceptorRegistry registry) {
        registry.addInterceptor(psuFilter()).addPathPatterns(pathPatterns);
      }
    };
  }

  @Bean
  WebSecurityConfigurerAdapter psuWebSecurityConfigurerAdapter() {
    return new WebSecurityConfigurerAdapterExtension();
  }
}
