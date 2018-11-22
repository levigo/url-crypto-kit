package com.neverpile.urlcrypto;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.validation.constraints.NotEmpty;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Component
@ConfigurationProperties(prefix = "neverpile.url-crypto")
@Validated
public class UrlCryptoConfiguration {
  private String enablePreSignedUrlAnnotationClass = PreSignedUrlEnabled.class.getName();

  private final SharedSecretConfiguration sharedSecret = new SharedSecretConfiguration();
  
  private Duration maxPreSignedValidity = Duration.ofDays(30);
  
  private List<String> pathPatterns = new ArrayList<>(Arrays.asList("/**"));
  
  public static class SharedSecretConfiguration {
    private boolean enabled;
    
    @NotEmpty
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
}
