package com.neverpile.urlcrypto;

import java.security.GeneralSecurityException;
import java.time.Duration;

import jakarta.servlet.http.HttpServletRequest;

/**
 * The PreSignedUrlCryptoKit handles the cryptographical part of pre-signed-URL generation and
 * verification.
 */
public interface UrlCryptoKit {
  String DURATION = "X-NPE-PSU-Duration";
  String CREDENTIAL = "X-NPE-PSU-Credential";
  String EXPIRES = "X-NPE-PSU-Expires";
  String SIGNATURE = "X-NPE-PSU-Signature";
  String DATE_PATTERN = "yyyyMMddHHmmss";

  /**
   * Generate a pre-signed URL for the given requested URL with the given validity duration.
   * 
   * @param validityDuration the requested validity duration
   * @param requestedUrl the URL
   * @return a pre-signed URL
   * @throws GeneralSecurityException on any crypto-related failure
   */
  String generatePreSignedUrl(Duration validityDuration, String requestedUrl) throws GeneralSecurityException;

  /**
   * Retrieve pre-signed request information from the given {@link HttpServletRequest}.
   * 
   * @param request the request @return the details of the request as extracted from the
   *          signature @throws InvalidSignatureException if the request does not contain a
   *          pre-signed signature @throws
   * @return the extracted pre-signed request information
   */
  PreSignedRequest getPreSignedRequest(HttpServletRequest request);

  /**
   * Validate the given pre-singed request information against the given {@link HttpServletRequest}.
   * 
   * @param preSignedRequest the pre-signed request
   * @param request the servlet request
   * @throws InvalidSignatureException if the signature in the request is invalid
   * @throws ExpiredException if the pre-signed request has expired
   */
  void validatePreSignedRequest(PreSignedRequest preSignedRequest, HttpServletRequest request);

  /**
   * Return whether the given request contains a pre-signed request.
   * 
   * @param request the incoming request
   * @return <code>true</code> if the request is pre-signed
   */
  boolean isPreSigned(HttpServletRequest request);

  /**
   * Encrypt the given URL so that it can be decrypted later. Limit the validity period to the given
   * duration. Do not limit it, if the duration is <code>null</code>.
   * 
   * @param validityDuration the validity period for the encrypted URL or <code>null</code> if the
   *          validity shall not be limited
   * @param url the url to encrypt
   * @return the encrypted URL ciphertext as a Base64 string
   * @throws GeneralSecurityException on any crypto-related failure
   */
  String encryptUrl(Duration validityDuration, String url) throws GeneralSecurityException;

  /**
   * Decrypt a URL that has been encrypted using {@link #encryptUrl(Duration, String)}. If you want
   * handle expiry more gracefully when decrypting, use to {@link #decryptUrl(String, Duration)}.
   * 
   * @param encrypted the encrypted URL ciphertext as a Base64 string
   * @return the decrypted URL
   * @throws GeneralSecurityException on any crypto-related failure
   * @throws ExpiredException if the encrypted URL has a limited validity which has expired
   */
  String decryptUrl(String encrypted) throws GeneralSecurityException;

  /**
   * Decrypt a URL that has been encrypted using {@link #encryptUrl(Duration, String)}. In contrast
   * to {@link #decryptUrl(String)} we can specify how graceful we handle the expiry timestamp.
   * 
   * @param encrypted the encrypted URL ciphertext as a Base64 string
   * @param gracePeriod how long we allow the validityDuration (specified when encrypting) to be
   *          exceeded
   * @return the decrypted URL
   * @throws GeneralSecurityException on any crypto-related failure
   * @throws ExpiredException if the encrypted URL has a limited validity which has expired
   */
  String decryptUrl(String encrypted, Duration gracePeriod) throws GeneralSecurityException;
}
