package com.neverpile.urlcrypto.springsecurity;

import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.neverpile.urlcrypto.config.UrlCryptoAutoConfiguration;

@SpringBootConfiguration
@EnableAutoConfiguration
@EnableWebSecurity
@Import({UrlCryptoAutoConfiguration.class, DummyResource.class})
@Order(SecurityProperties.BASIC_AUTH_ORDER)
public class TestConfiguration {
  @Bean
  SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http //
        .csrf().disable() //
        .httpBasic().and() //
        .authorizeRequests() //
        .antMatchers("/**").hasRole("USER");
    return http.build();
  }

  @Bean
  public InMemoryUserDetailsManager userDetailsService() {
    @SuppressWarnings("deprecation") // deprecation is a hint to not use this in production
    UserDetails user = User.withDefaultPasswordEncoder() //
        .username("user") //
        .password("password") //
        .roles("USER", "FOO", "BAR") //
        .build();
    return new InMemoryUserDetailsManager(user);
  }
}
