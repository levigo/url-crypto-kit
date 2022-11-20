package com.neverpile.urlcrypto.config;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import com.neverpile.urlcrypto.PreSignedUrlEnabled;

@Component
@ConfigurationProperties(prefix = "neverpile.url-crypto")
@Validated
public class UrlCryptoConfiguration {
  private String enablePreSignedUrlAnnotationClass = PreSignedUrlEnabled.class.getName();

  private final SharedSecretConfiguration sharedSecret = new SharedSecretConfiguration();

  private Duration maxPreSignedValidity = Duration.ofDays(30);

  private List<String> pathPatterns = new ArrayList<>(Collections.singletonList("/**"));

  private List<String> enabledStaticPaths = new ArrayList<>();

  public static class SharedSecretConfiguration {
    private boolean enabled;

    private String secretKey;

    public boolean isEnabled() {
      return enabled;
    }

    public void setEnabled(final boolean enabled) {
      this.enabled = enabled;
    }

    public String getSecretKey() {
      return secretKey;
    }

    public void setSecretKey(final String secretKey) {
      this.secretKey = secretKey;
    }
  }

  public SharedSecretConfiguration getSharedSecret() {
    return sharedSecret;
  }

  public String getEnablePreSignedUrlAnnotationClass() {
    return enablePreSignedUrlAnnotationClass;
  }

  public void setEnablePreSignedUrlAnnotationClass(final String enablePreSignedUrlAnnotationClass) {
    this.enablePreSignedUrlAnnotationClass = enablePreSignedUrlAnnotationClass;
  }

  public Duration getMaxPreSignedValidity() {
    return maxPreSignedValidity;
  }

  public void setMaxPreSignedValidity(final Duration maxPreSignedValidity) {
    this.maxPreSignedValidity = maxPreSignedValidity;
  }

  public List<String> getPathPatterns() {
    return pathPatterns;
  }

  public void setPathPatterns(final List<String> pathPatterns) {
    this.pathPatterns = pathPatterns;
  }

  public List<String> getEnabledStaticPaths() {
    return enabledStaticPaths;
  }

  public void setEnabledStaticPaths(List<String> enabledStaticPaths) {
    this.enabledStaticPaths = enabledStaticPaths;
  }
}
