package com.neverpile.urlcrypto.springsecurity;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.springframework.web.util.UriUtils.decode;

import java.net.URI;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.neverpile.urlcrypto.impl.SharedSecretCryptoKit;

import io.restassured.RestAssured;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {"neverpile.url-crypto.shared-secret.enabled=true",
        "neverpile.url-crypto.max-pre-signed-validity=PT24H", "neverpile.url-crypto.shared-secret.secret-key=foobar"
    })
public class PreSignedUrlTest {
  @LocalServerPort
  int port;

  @Autowired
  SharedSecretCryptoKit kit;

  @BeforeEach
  public void setupRestAssured() {
    System.out.println("Port:" + port);
    RestAssured.port = port;
    RestAssured.baseURI = "http://localhost";
  }

  @Test
  public void testThat_dummyResourceRequiresAuthentication() {
    // @formatter:off
    RestAssured
      .when()
        .get("/foo")
      .then()
        .statusCode(HttpStatus.UNAUTHORIZED.value());
    // @formatter:on
  }

  @Test
  public void testThat_dummyResourceCanBeAccessedWithAuthentication() {
    // @formatter:off
    RestAssured
      .given()
        .auth().preemptive().basic("user", "password")
      .when()
        .get("/foo")
      .then()
        .statusCode(200)
        .body(equalTo("foo"));
    // @formatter:on
  }

  @Test
  public void testThat_PSUCanBeGeneratedWithAuthentication() {
    ZonedDateTime startOfRequest = ZonedDateTime.now(ZoneOffset.UTC);

    URI psu = createPSU("/foo", "PT24H");

    assertThat(psu) //
        .hasPath("/foo") //
        .hasParameter("X-NPE-PSU-Expires") //
        .hasParameter("X-NPE-PSU-Signature") //
        .hasParameter("X-NPE-PSU-Credential") //
    ;

    Map<String, String> queryParams = parseQuery(psu);

    // validate expiry time
    assertThat(kit.parseExpiryTime(queryParams.get("X-NPE-PSU-Expires"))) //
        .isAfter(startOfRequest.plusDays(1).minusMinutes(1)) //
        .isBefore(startOfRequest.plusDays(1).plusMinutes(1));
  }

  @Test
  public void testThat_PSUValidityHonorsMaxValue() {
    ZonedDateTime startOfRequest = ZonedDateTime.now(ZoneOffset.UTC);

    // we request two days but expect to be given only 24h
    URI psu = createPSU("/foo", "PT48H");

    assertThat(psu) //
        .hasParameter("X-NPE-PSU-Expires") //
    ;

    Map<String, String> queryParams = parseQuery(psu);

    // validate expiry time (must be ~24H)
    assertThat(kit.parseExpiryTime(queryParams.get("X-NPE-PSU-Expires"))) //
        .isAfter(startOfRequest.plusDays(1).minusMinutes(1)) //
        .isBefore(startOfRequest.plusDays(1).plusMinutes(1));
  }

  @Test
  public void testThat_PSUCanBeUsedToAccessResource() {
    URI psu = createPSU("/foo", "PT24H");

    // @formatter:off
    RestAssured
      .given()
        .params(parseQuery(psu))
      .when()
        .get(psu.getPath())
      .then()
        .statusCode(200)
        .body(equalTo("foo"));
    // @formatter:on
  }

  @Test
  public void testThat_PSUTransportsCredentials() {
    URI psu = createPSU("/bar", "PT24H");

    // @formatter:off
    RestAssured
      .given()
        .params(parseQuery(psu))
      .when()
        .get(psu.getPath())
      .then()
        .statusCode(200)
        .body(equalTo("user/[ROLE_BAR, ROLE_FOO, ROLE_USER]"));
    // @formatter:on
  }

  @Test
  public void testThat_modifyingSignatureBreaksPSU() {
    URI uri = createPSU("/foo", "PT24H");

    Map<String, String> query = parseQuery(uri);

    byte[] sig = Hex.decode(query.get("X-NPE-PSU-Signature"));
    sig[0] ^= (byte) 0xcc;
    query.put("X-NPE-PSU-Signature", new String(Hex.encode(sig)));

    // @formatter:off
    RestAssured
      .given()
        .params(query)
      .when()
        .get("/foo")
      .then()
        .statusCode(401);
    // @formatter:on
  }

  @Test
  public void testThat_modifyingCredentialsBreaksPSU() {
    URI uri = createPSU("/foo", "PT24H");

    Map<String, String> query = parseQuery(uri);

    byte[] cred = Base64.getDecoder().decode(query.get("X-NPE-PSU-Credential"));
    cred[0] ^= (byte) 0xcc;
    query.put("X-NPE-PSU-Credential", Base64.getEncoder().encodeToString(cred));

    // @formatter:off
    RestAssured
      .given()
        .params(query)
      .when()
        .get("/foo")
      .then()
        .statusCode(401);
    // @formatter:on
  }

  @Test
  public void testThat_modifyingPathBreaksPSU() {
    URI uri = createPSU("/foo", "PT24H");

    // @formatter:off
    RestAssured
      .given()
        .params(parseQuery(uri))
      .when()
        .get("/bar")
      .then()
        .statusCode(401);
    // @formatter:on
  }

  @Test
  public void testThat_modifyingExpiryTimeBreaksPSU() {
    URI uri = createPSU("/foo", "PT24H");

    Map<String, String> query = parseQuery(uri);

    ZonedDateTime expiry = kit.parseExpiryTime(query.get("X-NPE-PSU-Expires"));
    expiry = expiry.plusDays(1);
    query.put("X-NPE-PSU-Signature", kit.encodeExpiryTime(expiry));

    // @formatter:off
    RestAssured
      .given()
        .params(query)
      .when()
        .get("/foo")
      .then()
        .statusCode(401);
    // @formatter:on
  }

  @Test
  public void testThat_PSUExpiresAfterExpiryTime() throws Exception {
    URI uri = createPSU("/foo", "PT2S");

    // @formatter:off
    RestAssured
      .given()
        .params(parseQuery(uri))
      .when()
        .get("/foo")
      .then()
        .statusCode(200);
    // @formatter:on

    // wait for expiry
    Thread.sleep(3000);

    // @formatter:off
    RestAssured
      .given()
        .params(parseQuery(uri))
      .when()
        .get("/foo")
      .then()
        .statusCode(401);
    // @formatter:on
  }

  private URI createPSU(final String path, final String expiry) {
    // @formatter:off
    String psu = RestAssured
      .given()
        .auth().preemptive().basic("user", "password")
        .param("X-NPE-PSU-Duration", expiry)
      .when()
        .get(path)
      .then()
        .statusCode(200)
        .body(not(equalTo("foo")))
        .extract().asString();
    // @formatter:on

    return URI.create(psu.trim());
  }

  private Map<String, String> parseQuery(final URI uri) {
    final Map<String, String> result = new LinkedHashMap<>();

    for (String pair : uri.getQuery().split("&")) {
      String[] keyValue = pair.split("=", 2);
      final String key = decode(keyValue[0], UTF_8);
      if (keyValue.length > 1) {
        result.put(key, decode(keyValue[1], UTF_8));
      }
    }

    return result;
  }

  @Test
  public void testThat_PSUCannotBeGeneratedWithoutAuthentication() {
    // @formatter:off
    RestAssured
      .given()
        .param("X-NPE-PSU-Duration", "PT24H")
      .when()
        .get("/foo")
      .then()
        .statusCode(HttpStatus.UNAUTHORIZED.value());
    // @formatter:on
  }

  @Test
  public void testThat_PSUCannotBeGeneratedForMethodsWithoutAnnotation() {
    // @formatter:off
    RestAssured
      .given()
        .param("X-NPE-PSU-Duration", "PT24H")
        .auth().preemptive().basic("user", "password")
      .when()
        .get("/baz")
      .then()
        .statusCode(HttpStatus.UNAUTHORIZED.value());
    // @formatter:on
  }
}
