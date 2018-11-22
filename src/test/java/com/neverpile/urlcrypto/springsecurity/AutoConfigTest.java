package com.neverpile.urlcrypto.springsecurity;

import static org.assertj.core.api.Assertions.*;

import org.junit.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.logging.ConditionEvaluationReportLoggingListener;
import org.springframework.boot.logging.LogLevel;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;

import com.neverpile.urlcrypto.UrlCryptoKit;
import com.neverpile.urlcrypto.config.UrlCryptoAutoConfiguration;
import com.neverpile.urlcrypto.impl.SharedSecretCryptoKit;

public class AutoConfigTest {
  private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner() //
      .withConfiguration(AutoConfigurations.of(UrlCryptoAutoConfiguration.class, //
          // emulate @EnableWebSecurity annotation presence
          WebSecurityConfiguration.class, AuthenticationConfiguration.class)) //
      .withInitializer(new ConditionEvaluationReportLoggingListener(LogLevel.DEBUG));

  @Test
  public void testThat_autoConfigurationIsActivatedByProperty() throws Exception {
    this.contextRunner //
        .withPropertyValues("neverpile.url-crypto.shared-secret.enabled=true") //
        .run((context) -> {
          assertThat(context).hasSingleBean(UrlCryptoKit.class);
          assertThat(context.getBean(UrlCryptoKit.class)).isInstanceOf(SharedSecretCryptoKit.class);
        });
  }
  
  @Test
  public void testThat_autoConfigurationIsNotActivatedOnMissingProperty() throws Exception {
    this.contextRunner //
    .withPropertyValues("neverpile.url-crypto.shared-secret.enabled=false") //
    .run((context) -> {
      assertThat(context).doesNotHaveBean(UrlCryptoKit.class);
    });
  }
}
