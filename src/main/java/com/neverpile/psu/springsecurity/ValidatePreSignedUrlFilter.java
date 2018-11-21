package com.neverpile.psu.springsecurity;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import com.neverpile.psu.PreSignedRequest;
import com.neverpile.psu.PreSignedUrlCryptoKit;

public class ValidatePreSignedUrlFilter extends OncePerRequestFilter {
  @Autowired
  private PreSignedUrlCryptoKit crypto;

  private AuthenticationManager authenticationManager;

  private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

  /**
   * This Method execute before the execution of the target resource. The system checks whether the
   * request includes a Pre Sign URL (PSU). If the order contains the parameter "X-NPE-PSU
   * signature", the method checks the expiration date, the signature and (currently not) the
   * validity of the authentication parameters. If all information is valid, the inquirer gets
   * access to the requested content.
   */
  @Override
  protected void doFilterInternal(HttpServletRequest request, final HttpServletResponse response,
      final FilterChain chain) throws ServletException, IOException {
    final boolean debug = this.logger.isDebugEnabled();

    String requestSignature = request.getParameter(PreSignedUrlCryptoKit.SIGNATURE);

    if (requestSignature == null) {
      chain.doFilter(request, response);
      return;
    }

    try {
      PreSignedRequest preSignedRequest = crypto.getPreSignedRequest(request);
      
      crypto.validatePreSignedRequest(preSignedRequest, request);

      if (debug) {
        this.logger.debug("Basic Authentication Authorization header found for user '" + preSignedRequest.getUsername() + "'");
      }
      
      if (isAuthenticationRequired()) {
        PreAuthenticatedAuthenticationToken authRequest = new PreAuthenticatedAuthenticationToken(preSignedRequest.getUsername(),
            preSignedRequest, preSignedRequest.getAuthorities());
        authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
        
        // Authentication authResult = this.authenticationManager.authenticate(authRequest);
        
        if (debug) {
          this.logger.debug("Authentication success: " + authRequest);
        }
        
        SecurityContextHolder.getContext().setAuthentication(authRequest);
      }
      
      /*
       * TODO - Currently, only the validity period and signature are checked. A further
       * verification whether the rights are still valid is still missing at this point.
       */
      request = new ParameterFilteringHttpServletRequestWrapper(request, k -> k.startsWith("X-NPE-PSU"));
    } catch (AuthenticationException e) {
      SecurityContextHolder.clearContext();

      if (debug) {
        this.logger.debug("Pre-signed URL valudation failed: ", e);
      }

      response.sendError(HttpStatus.UNAUTHORIZED.value(), e.getMessage());
      return;
    }

    chain.doFilter(request, response);
  }

  private boolean isAuthenticationRequired() {
    // apparently filters have to check this themselves. So make sure they have a proper
    // AuthenticatedAccount in their session.
    Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();

    // true if session is not already authenticated
    return (existingAuth == null) || !existingAuth.isAuthenticated();
  }

  public AuthenticationManager getAuthenticationManager() {
    return authenticationManager;
  }

  public void setAuthenticationManager(final AuthenticationManager authenticationManager) {
    this.authenticationManager = authenticationManager;
  }
}
