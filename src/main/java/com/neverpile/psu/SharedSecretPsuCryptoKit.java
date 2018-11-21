package com.neverpile.psu;

import static java.nio.charset.StandardCharsets.*;
import static java.time.Duration.parse;
import static java.time.ZonedDateTime.*;
import static java.time.ZonedDateTime.from;
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
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriUtils;

/**
 * The PreSignedUrlCryptoKit handles the cryptographical part of pre-signed-URL generation and
 * verification.
 */
@Component
@ConfigurationProperties(prefix = "neverpile-eureka.pre-signed-urls", ignoreUnknownFields = true)
public class SharedSecretPsuCryptoKit implements PreSignedUrlCryptoKit {
  private static final Logger log = LoggerFactory.getLogger(SharedSecretPsuCryptoKit.class);

  public static final String DURATION = "X-NPE-PSU-Duration";
  public static final String CREDENTIAL = "X-NPE-PSU-Credential";
  public static final String EXPIRES = "X-NPE-PSU-Expires";
  public static final String SIGNATURE = "X-NPE-PSU-Signature";
  static final String DATE_PATTERN = "yyyyMMddHHmmss";

  private final String ALGO = "AES/CBC/PKCS5Padding";
  private final String AESALGO = "AES";
  private final String HMACALGO = "HmacSHA256";
  private final int ivSize = 16;
  private final int keySize = 16;

  private final DateTimeFormatter pattern = DateTimeFormatter.ofPattern(DATE_PATTERN).withZone(ZoneOffset.UTC);

  private final SecureRandom random;

  private String secretKey;
  private boolean enabled;
  private String[] patterns;

  public SharedSecretPsuCryptoKit() {
    this.random = new SecureRandom();
  }

  @PostConstruct
  public void init() {
    if (null == secretKey || secretKey.equals(""))
      log.error("The secret key hasn't been configured. Using Pre-Signed-URLs is not safe!");
  }

  /**
   * @param parts The Pre Signed URL(PSU) signature has the following chronology: path, expiresAt,
   *          encodedAuthentication
   * @return returns a hashed signature
   * @throws GeneralSecurityException Generates a Signature with Message Authentication Code (HMAC)
   *           using the SHA256 hash function.
   */
  private String buildSignature(final String... parts) throws GeneralSecurityException {
    Mac sha256_HMAC = Mac.getInstance(this.HMACALGO);
    Key secretKey = generateHashedSecretKey(this.HMACALGO);
    sha256_HMAC.init(secretKey);

    return new String(Hex.encode(sha256_HMAC.doFinal(String.join("", parts).getBytes(StandardCharsets.UTF_8))));
  }

  /**
   * Takes a String and encrypts it using AES/CBC/PKCS5PADDING as transformation
   *
   * @param plaintext the plaintext to encrypt
   * @return the ciphertext
   * @throws GeneralSecurityException on any crypto-related failure
   */
  private String encrypt(final String plaintext) throws GeneralSecurityException {
    byte plaintextBytes[] = compress(plaintext.getBytes(StandardCharsets.UTF_8));

    Key secretKeySpec = generateHashedSecretKey(this.AESALGO);
    byte[] salt = generateRandomIv();
    IvParameterSpec ivParameterSpec = new IvParameterSpec(salt);

    // Encrypt.
    Cipher cipher = Cipher.getInstance(this.ALGO);
    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
    byte[] encrypted = cipher.doFinal(plaintextBytes);

    // Combine IV and encrypted part.
    byte[] encryptedIVAndText = new byte[this.ivSize + encrypted.length];
    System.arraycopy(salt, 0, encryptedIVAndText, 0, this.ivSize);
    System.arraycopy(encrypted, 0, encryptedIVAndText, this.ivSize, encrypted.length);

    return Base64.getEncoder().encodeToString(encryptedIVAndText);
  }

  private byte[] compress(final byte[] data) {
    byte[] output = new byte[data.length * 2];
    Deflater compresser = new Deflater();
    compresser.setInput(data);
    compresser.finish();
    int compressedDataLength = compresser.deflate(output);
    compresser.end();

    return Arrays.copyOf(output, compressedDataLength);
  }

  /**
   * Takes a byte and decrypt it using AES/CBC/PKCS5PADDING as transformation
   *
   * @param ciphertext the ciphertext
   * @return the plaintext
   * @throws GeneralSecurityException on any crypto-related failure
   * @throws DataFormatException on compresstion-related failures
   */
  private String decrypt(final byte[] ciphertext) throws GeneralSecurityException, DataFormatException {
    Key secretKeySpec = generateHashedSecretKey(this.AESALGO);

    // Extract IV.
    byte[] iv = new byte[this.ivSize];
    System.arraycopy(ciphertext, 0, iv, 0, iv.length);
    IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

    // Extract encrypted part.
    int encryptedSize = ciphertext.length - this.ivSize;
    byte[] encryptedBytes = new byte[encryptedSize];
    System.arraycopy(ciphertext, this.ivSize, encryptedBytes, 0, encryptedSize);

    // Decrypt.
    Cipher cipherDecrypt = Cipher.getInstance(this.ALGO);
    cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
    byte[] decrypted = cipherDecrypt.doFinal(encryptedBytes);

    return new String(decompress(decrypted), StandardCharsets.UTF_8);
  }

  private byte[] decompress(final byte[] data) throws DataFormatException {
    Inflater decompresser = new Inflater();
    decompresser.setInput(data);

    int chunkSize = data.length;
    int decompressed = 0;
    byte[] result = new byte[data.length];

    while (true) {
      int resultLength = decompresser.inflate(result, decompressed, chunkSize);
      decompressed += resultLength;
      if (resultLength < chunkSize) {
        decompresser.end();
        break;
      }

      result = Arrays.copyOf(result, result.length * 2);
    }

    return Arrays.copyOf(result, decompressed);
  }

  /**
   * @param algorithm the algorithm name
   * @return the hashed key
   * @throws NoSuchAlgorithmException Can be used to construct a SecretKey from a 16 byte long byte
   *           array and the specified algorithm. The byte array used is generated using the
   *           MessageDigest.class, the SHA-256 algorithm and the secretKey.
   */
  private Key generateHashedSecretKey(final String algorithm) throws NoSuchAlgorithmException {
    byte[] keyBytes = new byte[this.keySize];
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(getSecretKey().getBytes(StandardCharsets.UTF_8));
    System.arraycopy(md.digest(), 0, keyBytes, 0, keyBytes.length);
    return new SecretKeySpec(keyBytes, algorithm);
  }

  private ZonedDateTime getExpiryTime(final HttpServletRequest request) {
    return parseExpiryTime(request.getParameter(SharedSecretPsuCryptoKit.EXPIRES));
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
    byte[] iv = new byte[this.ivSize];
    random.nextBytes(iv);
    return iv;
  }

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(final boolean enabled) {
    this.enabled = enabled;
  }

  public String[] getPatterns() {
    return patterns;
  }

  public void setPatterns(final String[] patterns) {
    this.patterns = patterns;
  }

  public String getSecretKey() {
    return secretKey;
  }

  public void setSecretKey(final String secretKey) {
    this.secretKey = secretKey;
  }

  /* (non-Javadoc)
   * @see com.neverpile.psu.PreSignedUrlCryptoKit#generatePreSignedUrl(java.time.Duration, java.lang.String)
   */
  public String generatePreSignedUrl(final Duration expiryTime, final String requestedUrl)
      throws GeneralSecurityException {
    // Calculate expiry time
    ZonedDateTime expireTime = from(expiryTime.addTo(now(ZoneOffset.UTC)));
    String expiresAt = encodeExpiryTime(expireTime);

    // Encrypt Authorities
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

    String encodedAuthorization = encrypt(serializePrincipalAndRoles(authentication));

    // Build Signature
    String signature = buildSignature(requestedUrl, expiresAt, encodedAuthorization);

    // Build Pre-Sign Url
    String url = this.generatePreSignUrl(requestedUrl, encodedAuthorization, expiresAt, signature);
    return url;
  }

  private String serializePrincipalAndRoles(final Authentication authentication) {
    StringBuilder builder = new StringBuilder();
    builder.append(authentication.getName()).append("\n");
    authentication.getAuthorities().forEach(a -> builder.append(a).append("\n"));
    return builder.toString();
  }

  /**
   * Generates a Pre Sign Url from the given parameters.
   *
   * @param expiresAt format: "yyyy-MM-dd HH:mm:ss.SSSSSS"
   */
  private String generatePreSignUrl(final String requestedUrl, final String encryptedAuthorization,
      final String expiresAt, final String signature) {

    Map<String, String> responseUrlParams = new HashMap<>();
    responseUrlParams.put(SharedSecretPsuCryptoKit.CREDENTIAL, encryptedAuthorization);
    responseUrlParams.put(SharedSecretPsuCryptoKit.EXPIRES, expiresAt);
    responseUrlParams.put(SharedSecretPsuCryptoKit.SIGNATURE, signature);

    return responseUrlParams.keySet().stream().map(
        key -> key + "=" + UriUtils.encode(responseUrlParams.get(key), UTF_8)).collect(
            joining("&", requestedUrl + "?", ""));
  }

  /* (non-Javadoc)
   * @see com.neverpile.psu.PreSignedUrlCryptoKit#getPreSignedRequest(javax.servlet.http.HttpServletRequest)
   */
  public PreSignedRequest getPreSignedRequest(final HttpServletRequest request) {
    String path = request.getRequestURL().toString();

    PreSignedRequest psuPayload;

    ZonedDateTime expiryTime = getExpiryTime(request);
    try {
      // Decrypt Authorities
      String encodedAuthentication = request.getParameter(PreSignedUrlCryptoKit.CREDENTIAL);

      // Signature
      String signature = buildSignature(path, request.getParameter(PreSignedUrlCryptoKit.EXPIRES),
          encodedAuthentication);

      String decryptedAuthentication = decrypt(Base64.getDecoder().decode(encodedAuthentication));
      String[] authentication = decryptedAuthentication.split("\n");

      String username = authentication[0];
      List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>(authentication.length - 1);
      for (int i = 1; i < authentication.length; i++) {
        authorities.add(new SimpleGrantedAuthority(authentication[i]));
      }

      psuPayload = new PreSignedRequest(expiryTime, username, signature, authorities);
    } catch (GeneralSecurityException | DataFormatException e) {
      throw new InternalAuthenticationServiceException("Can't authenticate", e);
    }

    return psuPayload;
  }

  /* (non-Javadoc)
   * @see com.neverpile.psu.PreSignedUrlCryptoKit#validatePreSignedRequest(com.neverpile.psu.PreSignedRequest, javax.servlet.http.HttpServletRequest)
   */
  @Override
  public void validatePreSignedRequest(final PreSignedRequest preSignedRequest, final HttpServletRequest request) {
    if (preSignedRequest.getExpiryTime().isBefore(ZonedDateTime.now())) {
      throw new TokenExpiredException("The pre-signed URL has expired");
    }

    if (!preSignedRequest.getSignature().equals(request.getParameter(PreSignedUrlCryptoKit.SIGNATURE))) {
      throw new InvalidSignatureException("The provided signature is invalid");
    }
  }
}
