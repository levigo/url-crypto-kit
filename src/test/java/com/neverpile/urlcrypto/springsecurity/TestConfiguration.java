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
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.neverpile.urlcrypto.config.UrlCryptoAutoConfiguration;

@SpringBootConfiguration
@EnableAutoConfiguration
@EnableWebSecurity(debug = true)
@Import({UrlCryptoAutoConfiguration.class, DummyResource.class})
public class TestConfiguration {
  @Bean
  SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    System.out.println("AAAAA");
    http //
        .csrf(AbstractHttpConfigurer::disable)
        .httpBasic(Customizer.withDefaults())
        .authorizeHttpRequests(auth -> //
            auth.requestMatchers("/**").hasRole("USER"));
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
