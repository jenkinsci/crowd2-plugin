/*
 * @(#)CrowdRememberMeServices.java
 * 
 * The MIT License
 * 
 * Copyright (C)2011 Thorsten Heit.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package de.theit.jenkins.crowd;

import static de.theit.jenkins.crowd.ErrorMessages.accountExpired;
import static de.theit.jenkins.crowd.ErrorMessages.applicationAccessDenied;
import static de.theit.jenkins.crowd.ErrorMessages.applicationPermission;
import static de.theit.jenkins.crowd.ErrorMessages.expiredCredentials;
import static de.theit.jenkins.crowd.ErrorMessages.invalidAuthentication;
import static de.theit.jenkins.crowd.ErrorMessages.operationFailed;
import hudson.security.SecurityRealm;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.ui.rememberme.RememberMeServices;

import com.atlassian.crowd.exception.ApplicationAccessDeniedException;
import com.atlassian.crowd.exception.ApplicationPermissionException;
import com.atlassian.crowd.exception.ExpiredCredentialException;
import com.atlassian.crowd.exception.InactiveAccountException;
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.InvalidTokenException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.model.authentication.ValidationFactor;
import com.atlassian.crowd.model.user.User;

/**
 * An implementation of the {@link RememberMeServices} to use SSO with Crowd.
 * 
 * @author <a href="mailto:theit@gmx.de">Thorsten Heit (theit@gmx.de)</a>
 * @since 06.09.2011
 * @version $Id$
 */
public class CrowdRememberMeServices implements RememberMeServices {
	/** Used for logging purposes. */
	private static final Logger LOG = Logger
			.getLogger(CrowdRememberMeServices.class.getName());

	/**
	 * The configuration data necessary for accessing the services on the remote
	 * Crowd server.
	 */
	private CrowdConfigurationService configuration;

	/**
	 * Creates a new instance of this class.
	 * 
	 * @param pConfiguration
	 *            The configuration to access the services on the remote Crowd
	 *            server. May not be <code>null</code>.
	 */
	public CrowdRememberMeServices(CrowdConfigurationService pConfiguration) {
		this.configuration = pConfiguration;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @see org.acegisecurity.ui.rememberme.RememberMeServices#autoLogin(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	@Override
	public Authentication autoLogin(HttpServletRequest request,
			HttpServletResponse response) {
		Authentication result = null;

		List<ValidationFactor> validationFactors = this.configuration.tokenHelper
				.getValidationFactorExtractor().getValidationFactors(request);

		// check whether a SSO token is available
		if (LOG.isLoggable(Level.FINER)) {
			LOG.finer("Checking whether a SSO token is available...");
		}
		String ssoToken = this.configuration.tokenHelper.getCrowdToken(request,
				this.configuration.clientProperties.getCookieTokenKey());

		// auto-login is only possible when the SSO token was found
		if (null != ssoToken) {
			try {
				// SSO token available => check whether it is still valid
				if (LOG.isLoggable(Level.FINER)) {
					LOG.finer("SSO token available => check whether it is still valid...");
				}
				this.configuration.crowdClient.validateSSOAuthentication(
						ssoToken, validationFactors);

				// retrieve the user that is logged in via SSO
				if (LOG.isLoggable(Level.FINER)) {
					LOG.finer("Retrieving SSO user...");
				}
				User user = this.configuration.crowdClient
						.findUserFromSSOToken(ssoToken);

				// check whether the user is a member of the user group in Crowd
				// that specifies who is allowed to login
				if (LOG.isLoggable(Level.FINER)) {
					LOG.finer("Validating group membership of user...");
				}
				if (this.configuration.isGroupMember(user.getName())) {
					// user is authenticated and validated
					// => create the user object and finalize the auto-login
					// process
					List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
					authorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
					authorities.addAll(this.configuration
							.getAuthoritiesForUser(user.getName()));

					result = new CrowdAuthenticationToken(user.getName(), null,
							authorities, ssoToken, user.getDisplayName());
				}
			} catch (InvalidTokenException ex) {
				// LOG.log(Level.INFO, invalidToken(), ex);
			} catch (ApplicationPermissionException ex) {
				LOG.warning(applicationPermission());
			} catch (InvalidAuthenticationException ex) {
				LOG.warning(invalidAuthentication());
			} catch (OperationFailedException ex) {
				LOG.log(Level.SEVERE, operationFailed(), ex);
			}
		}

		return result;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @see org.acegisecurity.ui.rememberme.RememberMeServices#loginFail(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	@Override
	public void loginFail(HttpServletRequest request,
			HttpServletResponse response) {
		try {
			if (LOG.isLoggable(Level.FINE)) {
				LOG.fine("Login failed");
			}
			this.configuration.crowdHttpAuthenticator.logout(request, response);
		} catch (ApplicationPermissionException ex) {
			LOG.warning(applicationPermission());
		} catch (InvalidAuthenticationException ex) {
			LOG.warning(invalidAuthentication());
		} catch (OperationFailedException ex) {
			LOG.log(Level.SEVERE, operationFailed(), ex);
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @see org.acegisecurity.ui.rememberme.RememberMeServices#loginSuccess(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse,
	 *      org.acegisecurity.Authentication)
	 */
	@Override
	public void loginSuccess(HttpServletRequest request,
			HttpServletResponse response,
			Authentication successfulAuthentication) {
		if (!(successfulAuthentication instanceof CrowdAuthenticationToken)) {
			// authentication token doesn't belong to us...
			return;
		}
		CrowdAuthenticationToken crowdAuthenticationToken = (CrowdAuthenticationToken) successfulAuthentication;

		List<ValidationFactor> validationFactors = this.configuration.tokenHelper
				.getValidationFactorExtractor().getValidationFactors(request);

		// check if there's already a SSO token in the authentication object
		String ssoToken = crowdAuthenticationToken.getSSOToken();

		try {
			if (null == ssoToken) {
				// SSO token not yet available => authenticate the user and
				// create the SSO token
				if (LOG.isLoggable(Level.FINE)) {
					LOG.fine("SSO token not yet available => authenticate user...");
				}
				this.configuration.crowdHttpAuthenticator.authenticate(request,
						response, crowdAuthenticationToken.getPrincipal(),
						crowdAuthenticationToken.getCredentials());

				// user is successfully authenticated
				// => retrieve the SSO token
				if (LOG.isLoggable(Level.FINER)) {
					LOG.finer("Retrieve SSO token...");
				}
				ssoToken = this.configuration.tokenHelper
						.getCrowdToken(request,
								this.configuration.clientProperties
										.getCookieTokenKey());
			}

			if (null == ssoToken) {
				// SSO token could not be retrieved (should normally not happen)
				// => logout
				loginFail(request, response);
				return;
			}

			// validate the SSO authentication
			if (LOG.isLoggable(Level.FINE)) {
				LOG.fine("Validate the SSO authentication...");
			}
			this.configuration.crowdClient.validateSSOAuthentication(ssoToken,
					validationFactors);

			// alright, we're successfully authenticated via SSO
			if (LOG.isLoggable(Level.FINE)) {
				LOG.fine("Successfully authenticated via SSO");
			}
		} catch (InvalidTokenException ex) {
			// LOG.log(Level.INFO, invalidToken(), ex);
		} catch (ApplicationPermissionException ex) {
			LOG.warning(applicationPermission());
		} catch (InvalidAuthenticationException ex) {
			LOG.warning(invalidAuthentication());
		} catch (ExpiredCredentialException ex) {
			LOG.warning(expiredCredentials(crowdAuthenticationToken
					.getPrincipal()));
		} catch (InactiveAccountException ex) {
			LOG.warning(accountExpired(crowdAuthenticationToken.getPrincipal()));
		} catch (ApplicationAccessDeniedException ex) {
			LOG.warning(applicationAccessDenied(crowdAuthenticationToken
					.getPrincipal()));
		} catch (OperationFailedException ex) {
			LOG.log(Level.SEVERE, operationFailed(), ex);
		}
	}

	/**
	 * Logout the actual user and close the SSO session.
	 * 
	 * @param request
	 *            The servlet request. May not be <code>null</code>.
	 * @param response
	 *            The servlet response. May not be <code>null</code>.
	 */
	public void logout(HttpServletRequest request, HttpServletResponse response) {
		try {
			// logout the user and close the SSO session
			if (LOG.isLoggable(Level.FINE)) {
				LOG.fine("Logout user and close SSO session");
			}
			this.configuration.crowdHttpAuthenticator.logout(request, response);
		} catch (ApplicationPermissionException ex) {
			LOG.warning(applicationPermission());
		} catch (InvalidAuthenticationException ex) {
			LOG.warning(invalidAuthentication());
		} catch (OperationFailedException ex) {
			LOG.log(Level.SEVERE, operationFailed(), ex);
		}
	}
}
