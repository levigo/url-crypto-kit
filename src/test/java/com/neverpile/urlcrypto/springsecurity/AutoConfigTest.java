package com.neverpile.urlcrypto.springsecurity;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.logging.ConditionEvaluationReportLoggingListener;
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.webmvc.autoconfigure.WebMvcAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

import com.neverpile.urlcrypto.UrlCryptoKit;
import com.neverpile.urlcrypto.config.UrlCryptoAutoConfiguration;
import com.neverpile.urlcrypto.impl.SharedSecretCryptoKit;

public class AutoConfigTest {
  private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner() //
      .withConfiguration(AutoConfigurations.of(UrlCryptoAutoConfiguration.class, //
          SecurityAutoConfiguration.class, ServletWebSecurityAutoConfiguration.class, WebMvcAutoConfiguration.class)) //
      .withInitializer(new ConditionEvaluationReportLoggingListener());

  @Test
  public void testThat_autoConfigurationIsActivatedByProperty() {
    this.contextRunner //
        .withPropertyValues("neverpile.url-crypto.shared-secret.enabled=true") //
        .run((context) -> {
          assertThat(context).hasSingleBean(UrlCryptoKit.class);
          assertThat(context.getBean(UrlCryptoKit.class)).isInstanceOf(SharedSecretCryptoKit.class);
        });
  }

  @Test
  public void testThat_autoConfigurationIsNotActivatedOnMissingProperty() {
    this.contextRunner //
        .withPropertyValues("neverpile.url-crypto.shared-secret.enabled=false") //
        .run((context) -> assertThat(context).doesNotHaveBean(UrlCryptoKit.class));
  }

  @Test
  public void testThat_autoConfigurationIsActivateForNonWebAppToo() {
    new ApplicationContextRunner() //
        .withConfiguration(AutoConfigurations.of(UrlCryptoAutoConfiguration.class)) //
        .withInitializer(new ConditionEvaluationReportLoggingListener()) //
        .withPropertyValues("neverpile.url-crypto.shared-secret.enabled=true") //
        .run((context) -> {
          assertThat(context).hasSingleBean(UrlCryptoKit.class);
          assertThat(context.getBean(UrlCryptoKit.class)).isInstanceOf(SharedSecretCryptoKit.class);
        });
  }

}
