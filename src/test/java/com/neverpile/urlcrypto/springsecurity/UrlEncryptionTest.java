package com.neverpile.urlcrypto.springsecurity;

import static org.assertj.core.api.Assertions.*;

import java.net.URL;
import java.time.Duration;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import com.neverpile.urlcrypto.ExpiredException;
import com.neverpile.urlcrypto.impl.SharedSecretCryptoKit;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE, properties = {
    "neverpile.url-crypto.shared-secret.enabled=true", "neverpile.url-crypto.shared-secret.secret-key=foobar"
})
public class UrlEncryptionTest {
  @Autowired
  SharedSecretCryptoKit kit;

  @Test
  public void testThat_encryptedUrlCanBeDecrypted() throws Exception {
    URL url = new URL("https://foo.bar/baz?yada=foo");

    String ciphertext = kit.encryptUrl(Duration.parse("PT1H"), url.toExternalForm());

    assertThat(ciphertext).doesNotContain("foo.bar");

    String plaintext = kit.decryptUrl(ciphertext);

    assertThat(plaintext).isEqualTo(url.toExternalForm());
  }
  
  @Test
  public void testThat_encryptionUsesIV() throws Exception {
    URL url = new URL("https://foo.bar/baz?yada=foo");

    String ciphertext1 = kit.encryptUrl(Duration.parse("PT1H"), url.toExternalForm());
    String ciphertext2 = kit.encryptUrl(Duration.parse("PT1H"), url.toExternalForm());

    assertThat(ciphertext1).isNotEqualTo(ciphertext2);
  }

  @Test(expected = ExpiredException.class)
  public void testThat_encryptedUrlExpires() throws Exception {
    URL url = new URL("https://foo.bar/baz?yada=foo");

    String ciphertext = kit.encryptUrl(Duration.parse("PT1S"), url.toExternalForm());

    Thread.sleep(2000);
    
    kit.decryptUrl(ciphertext);
  }
}
