package com.neverpile.urlcrypto.impl;

import static java.nio.charset.StandardCharsets.*;
import static java.time.ZonedDateTime.*;
import static java.util.stream.Collectors.*;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import jakarta.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import jakarta.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriUtils;

import com.neverpile.urlcrypto.ExpiredException;
import com.neverpile.urlcrypto.InvalidSignatureException;
import com.neverpile.urlcrypto.PreSignedRequest;
import com.neverpile.urlcrypto.UrlCryptoKit;
import com.neverpile.urlcrypto.config.UrlCryptoConfiguration;

/**
 * The PreSignedUrlCryptoKit handles the cryptographical part of pre-signed-URL generation and
 * verification.
 */
public class SharedSecretCryptoKit implements UrlCryptoKit {
  private static final Logger log = LoggerFactory.getLogger(SharedSecretCryptoKit.class);

  private static final String ENCRYPTION_TRANSFORM = "AES/CBC/PKCS5Padding";
  private static final String AESALGO = "AES";
  private static final String HMACALGO = "HmacSHA256";

  private static final int IV_SIZE = 16;
  private static final int KEY_SIZE = 16;

  private final DateTimeFormatter pattern = DateTimeFormatter.ofPattern(DATE_PATTERN).withZone(ZoneOffset.UTC);

  private final SecureRandom random = new SecureRandom();

  @Autowired
  private UrlCryptoConfiguration configuration;

  private byte[] keyBytes;

  @PostConstruct
  public void init() throws NoSuchAlgorithmException {
    String secretKey;
    if (null == configuration.getSharedSecret().getSecretKey()
        || configuration.getSharedSecret().getSecretKey().equals("")) {
      secretKey = UUID.randomUUID().toString();

      log.warn("The secret key hasn't been configured - using randomly generated key {}. "
          + "Pre-Signed-URLs will not remain valid across server restarts", secretKey);
    } else
      secretKey = configuration.getSharedSecret().getSecretKey();

    // hash secret key into bytes used for encryption and HMAC.
    keyBytes = new byte[KEY_SIZE];
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(secretKey.getBytes(StandardCharsets.UTF_8));
    System.arraycopy(md.digest(), 0, keyBytes, 0, keyBytes.length);
  }

  /**
   * @param parts The Pre Signed URL(PSU) signature has the following chronology: path, expiresAt,
   *          encodedAuthentication
   * @return returns a hashed signature
   * @throws GeneralSecurityException Generates a Signature with Message Authentication Code (HMAC)
   *           using the SHA256 hash function.
   */
  private String buildSignature(final String... parts) throws GeneralSecurityException {
    Mac hmac = Mac.getInstance(HMACALGO);
    Key secretKey = new SecretKeySpec(keyBytes, HMACALGO);
    hmac.init(secretKey);

    return new String(Hex.encode(hmac.doFinal(String.join("", parts).getBytes(StandardCharsets.UTF_8))));
  }

  /**
   * Takes a String and encrypts it using AES/CBC/PKCS5PADDING as transformation
   *
   * @param plaintext the plaintext to encrypt
   * @return the ciphertext
   * @throws GeneralSecurityException on any crypto-related failure
   */
  private String encrypt(final String plaintext) throws GeneralSecurityException {
    byte[] plaintextBytes = compress(plaintext.getBytes(StandardCharsets.UTF_8));

    Key secretKeySpec = new SecretKeySpec(keyBytes, AESALGO);
    byte[] salt = generateRandomIv();
    IvParameterSpec ivParameterSpec = new IvParameterSpec(salt);

    // Encrypt.
    Cipher cipher = Cipher.getInstance(ENCRYPTION_TRANSFORM);
    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
    byte[] encrypted = cipher.doFinal(plaintextBytes);

    // Combine IV and encrypted part.
    byte[] encryptedIVAndText = new byte[IV_SIZE + encrypted.length];
    System.arraycopy(salt, 0, encryptedIVAndText, 0, IV_SIZE);
    System.arraycopy(encrypted, 0, encryptedIVAndText, IV_SIZE, encrypted.length);

    return Base64.getEncoder().encodeToString(encryptedIVAndText);
  }

  private byte[] compress(final byte[] data) {
    byte[] output = new byte[data.length * 2];
    Deflater compressor = new Deflater();
    compressor.setInput(data);
    compressor.finish();
    int compressedDataLength = compressor.deflate(output);
    compressor.end();

    return Arrays.copyOf(output, compressedDataLength);
  }

  /**
   * Decrypt a byte array of ciphertext and decrypt it using AES/CBC/PKCS5PADDING.
   *
   * @param ciphertext the ciphertext
   * @return the plaintext
   * @throws GeneralSecurityException on any crypto-related failure
   */
  private String decrypt(final String ciphertext) throws GeneralSecurityException {
    Key secretKeySpec = new SecretKeySpec(keyBytes, AESALGO);

    byte[] ciphertextBytes = Base64.getDecoder().decode(ciphertext);

    // Extract IV.
    byte[] iv = new byte[IV_SIZE];
    System.arraycopy(ciphertextBytes, 0, iv, 0, iv.length);
    IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

    // Extract encrypted part.
    int encryptedSize = ciphertextBytes.length - IV_SIZE;
    byte[] encryptedBytes = new byte[encryptedSize];
    System.arraycopy(ciphertextBytes, IV_SIZE, encryptedBytes, 0, encryptedSize);

    // Decrypt.
    Cipher cipherDecrypt = Cipher.getInstance(ENCRYPTION_TRANSFORM);
    cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
    byte[] decrypted = cipherDecrypt.doFinal(encryptedBytes);

    return new String(decompress(decrypted), StandardCharsets.UTF_8);
  }

  private byte[] decompress(final byte[] data) {
    Inflater decompresser = new Inflater();
    decompresser.setInput(data);

    int chunkSize = data.length;
    int decompressed = 0;
    byte[] result = new byte[data.length];

    try {
      while (true) {
        int resultLength = decompresser.inflate(result, decompressed, chunkSize);
        decompressed += resultLength;
        if (resultLength < chunkSize) {
          decompresser.end();
          break;
        }

        result = Arrays.copyOf(result, result.length * 2);
      }
    } catch (DataFormatException e) {
      throw new IllegalArgumentException("Invalid encrypted data", e);
    }

    return Arrays.copyOf(result, decompressed);
  }

  private ZonedDateTime getExpiryTime(final HttpServletRequest request) {
    return parseExpiryTime(request.getParameter(SharedSecretCryptoKit.EXPIRES));
  }

  // Visible for testing
  public ZonedDateTime parseExpiryTime(final String parameter) {
    return ZonedDateTime.parse(parameter, pattern);
  }

  // Visible for testing
  public String encodeExpiryTime(final ZonedDateTime expiry) {
    return pattern.format(expiry);
  }

  /**
   * Generates a byte array with a length of 16 bytes.
   *
   * @return byte[] with random content
   */
  private byte[] generateRandomIv() {
    byte[] iv = new byte[IV_SIZE];
    random.nextBytes(iv);
    return iv;
  }

  /*
   * (non-Javadoc)
   *
   * @see com.neverpile.psu.PreSignedUrlCryptoKit#generatePreSignedUrl(java.time.Duration,
   * java.lang.String)
   */
  public String generatePreSignedUrl(final Duration validityDuration, final String requestedUrl)
      throws GeneralSecurityException {
    // Calculate expiry time
    ZonedDateTime expiryTime = from(validityDuration.addTo(now(ZoneOffset.UTC)));
    String expiresAt = encodeExpiryTime(expiryTime);

    // Encrypt Authorities
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

    String encodedAuthorization = encrypt(serializePrincipalAndRoles(authentication));

    // Build Signature
    String signature = buildSignature(requestedUrl, expiresAt, encodedAuthorization);

    // Encode pre-signed Url
    Map<String, String> params = new HashMap<>();
    params.put(SharedSecretCryptoKit.CREDENTIAL, encodedAuthorization);
    params.put(SharedSecretCryptoKit.EXPIRES, expiresAt);
    params.put(SharedSecretCryptoKit.SIGNATURE, signature);

    // FIXME: this doesn't support URLs with existing query parameters. Is this a problem?
    return params.keySet().stream() //
        .map(key -> key + "=" + UriUtils.encode(params.get(key), UTF_8)) //
        .collect(joining("&", requestedUrl + "?", ""));
  }

  private String serializePrincipalAndRoles(final Authentication authentication) {
    StringBuilder builder = new StringBuilder();
    builder.append(authentication.getName()).append("\n");
    authentication.getAuthorities().forEach(a -> builder.append(a).append("\n"));
    return builder.toString();
  }

  /*
   * (non-Javadoc)
   *
   * @see com.neverpile.psu.PreSignedUrlCryptoKit#getPreSignedRequest(jakarta.servlet.http.
   * HttpServletRequest)
   */
  public PreSignedRequest getPreSignedRequest(final HttpServletRequest request) {
    String path = request.getRequestURL().toString();

    PreSignedRequest psuPayload;

    ZonedDateTime expiryTime = getExpiryTime(request);
    try {
      // Decrypt Authorities
      String encryptedCredentials = request.getParameter(UrlCryptoKit.CREDENTIAL);

      // Signature
      String signature = buildSignature(path, request.getParameter(UrlCryptoKit.EXPIRES), encryptedCredentials);

      String decryptedAuthentication = decrypt(encryptedCredentials);
      String[] authentication = decryptedAuthentication.split("\n");

      String username = authentication[0];
      List<GrantedAuthority> authorities = new ArrayList<>(authentication.length - 1);
      for (int i = 1; i < authentication.length; i++) {
        authorities.add(new SimpleGrantedAuthority(authentication[i]));
      }

      psuPayload = new PreSignedRequest(expiryTime, username, signature, authorities);
    } catch (GeneralSecurityException e) {
      throw new InternalAuthenticationServiceException("Can't authenticate", e);
    }

    return psuPayload;
  }

  /*
   * (non-Javadoc)
   *
   * @see com.neverpile.psu.PreSignedUrlCryptoKit#validatePreSignedRequest(com.neverpile.psu.
   * PreSignedRequest, jakarta.servlet.http.HttpServletRequest)
   */
  @Override
  public void validatePreSignedRequest(final PreSignedRequest preSignedRequest, final HttpServletRequest request) {
    if (preSignedRequest.getExpiryTime().isBefore(ZonedDateTime.now())) {
      throw new ExpiredException("The pre-signed URL has expired");
    }

    if (!preSignedRequest.getSignature().equals(request.getParameter(UrlCryptoKit.SIGNATURE))) {
      throw new InvalidSignatureException("The provided signature is invalid");
    }
  }

  /*
   * (non-Javadoc)
   *
   * @see com.neverpile.urlcrypto.UrlCryptoKit#isPreSigned(jakarta.servlet.http.HttpServletRequest)
   */
  @Override
  public boolean isPreSigned(final HttpServletRequest request) {
    return request.getParameter(UrlCryptoKit.SIGNATURE) != null;
  }

  /* (non-Javadoc)
   * @see com.neverpile.urlcrypto.UrlCryptoKit#encryptUrl(java.time.Duration, java.lang.String)
   */
  @Override
  public String encryptUrl(final Duration validityDuration, final String url) throws GeneralSecurityException {
    // Calculate expiry time
    String expiresAt;
    if (null != validityDuration) {
      ZonedDateTime expireTime = from(validityDuration.addTo(now(ZoneOffset.UTC)));
      expiresAt = encodeExpiryTime(expireTime);
    } else {
      expiresAt = "";
    }

    return encrypt(expiresAt + "|" + url);
  }

  /* (non-Javadoc)
   * @see com.neverpile.urlcrypto.UrlCryptoKit#decryptUrl(java.lang.String)
   */
  @Override
  public String decryptUrl(final String encrypted) throws GeneralSecurityException {
    return decryptUrl(encrypted, Duration.ofMillis(0));
  }

  /* (non-Javadoc)
   * @see com.neverpile.urlcrypto.UrlCryptoKit#decryptUrl(java.lang.String, Duration)
   */
  @Override
  public String decryptUrl(final String encrypted, Duration gracePeriod) throws GeneralSecurityException {
    String plaintext = decrypt(encrypted);

    String[] parts = plaintext.split("\\|", 2);
    if (parts.length != 2) {
      throw new IllegalArgumentException("Invalid encrypted URL");
    }

    String expiresAt = parts[0];
    if (!expiresAt.isEmpty()) {
      ZonedDateTime expiryTime = parseExpiryTime(expiresAt);

      if (expiryTime.plus(gracePeriod).isBefore(ZonedDateTime.now()))
        throw new ExpiredException("The encrypted URL has expired");
    }

    return parts[1];
  }
}
