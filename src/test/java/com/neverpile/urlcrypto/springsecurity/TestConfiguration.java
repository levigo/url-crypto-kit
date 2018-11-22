package com.neverpile.urlcrypto.springsecurity;

import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import com.neverpile.urlcrypto.PreSignedUrlSupportConfiguration;

@SpringBootConfiguration
@EnableAutoConfiguration
@EnableWebSecurity
@Import({
    PreSignedUrlSupportConfiguration.class, DummyResource.class
})
@Order(SecurityProperties.BASIC_AUTH_ORDER)
public class TestConfiguration extends WebSecurityConfigurerAdapter {
  @Override
  protected void configure(final HttpSecurity http) throws Exception {
    http //
        .csrf().disable() //
        .httpBasic().and() //
        .authorizeRequests() //
        .antMatchers("/**").hasRole("USER");
  }

  @Override
  public void configure(final AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication() //
        .withUser("user") //
        .password("{noop}password") //
        .roles("USER", "FOO", "BAR");
  }
}
