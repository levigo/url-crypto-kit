package com.neverpile.urlcrypto.springsecurity;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URL;
import java.time.Duration;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import com.neverpile.urlcrypto.impl.SharedSecretCryptoKit;

@RunWith(SpringRunner.class)
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.NONE,
    properties = {
        "neverpile.url-crypto.shared-secret.enabled=true"
    })
public class UrlEncryptionTestWithGeneratedKey {
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
