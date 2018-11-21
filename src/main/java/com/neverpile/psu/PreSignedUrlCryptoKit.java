package com.neverpile.psu;

import java.security.GeneralSecurityException;
import java.time.Duration;

import javax.servlet.http.HttpServletRequest;

/**
 * The PreSignedUrlCryptoKit handles the cryptographical part of pre-signed-URL generation and
 * verification.
 */
public interface PreSignedUrlCryptoKit {
  public static final String DURATION = "X-NPE-PSU-Duration";
  public static final String CREDENTIAL = "X-NPE-PSU-Credential";
  public static final String EXPIRES = "X-NPE-PSU-Expires";
  public static final String SIGNATURE = "X-NPE-PSU-Signature";
  static final String DATE_PATTERN = "yyyyMMddHHmmss";

  /**
   * Generate a pre-signed URL for the given requested URL with the the given validity duration.
   * 
   * @param validityDuration the requested validity duration
   * @param requestedUrl the URL 
   * @return a pre-signed URL
   * @throws GeneralSecurityException
   */
  String generatePreSignedUrl(final Duration validityDuration, final String requestedUrl)
      throws GeneralSecurityException;
  
  /**
   * Retrieve pre-singed request information from the given {@link HttpServletRequest}.
   * 
   * @param request the request
   * @return the details of the request as extracted from the signature
   * @throws InvalidSignatureException if the request does not contain a pre-signed signature
   * @throws 
   */
  PreSignedRequest getPreSignedRequest(final HttpServletRequest request);

  /**
   * Validate the given pre-singed request information against the given {@link HttpServletRequest}.
   * 
   * @param preSignedRequest the pre-signed request
   * @param request the servlet request
   * @throws InvalidSignatureException if the signature in the request is invalid
   * @throws TokenExpiredException if the pre-signed request has expired
   */
  void validatePreSignedRequest(final PreSignedRequest preSignedRequest, final HttpServletRequest request);
}
