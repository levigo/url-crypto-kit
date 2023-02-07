package com.neverpile.urlcrypto.springsecurity;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URL;
import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.neverpile.urlcrypto.impl.SharedSecretCryptoKit;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK,
    properties = {"neverpile.url-crypto.shared-secret.enabled=true"
    })
public class UrlEncryptionWithGeneratedKeyTest {
  @Autowired
  SharedSecretCryptoKit kit;

  /**
   * Test that when not configuring "neverpile.url-crypto.shared-secret.secret-key" a secret key is
   * auto-generated and used to encrypt the url.
   */
  @Test
  public void testThat_encryptedUrlCanBeDecrypted() throws Exception {
    URL url = new URL("https://foo.bar/baz?yada=foo");

    String ciphertext = kit.encryptUrl(Duration.parse("PT1H"), url.toExternalForm());

    assertThat(ciphertext).doesNotContain("foo.bar");

    String plaintext = kit.decryptUrl(ciphertext);

    assertThat(plaintext).isEqualTo(url.toExternalForm());
  }

}
