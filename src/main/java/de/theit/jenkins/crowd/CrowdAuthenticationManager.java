/*
 * @(#)CrowdAuthenticationManager.java
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

import com.atlassian.crowd.exception.ApplicationPermissionException;
import com.atlassian.crowd.exception.ExpiredCredentialException;
import com.atlassian.crowd.exception.InactiveAccountException;
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.exception.UserNotFoundException;
import com.atlassian.crowd.model.user.User;
import hudson.security.SecurityRealm;
import org.acegisecurity.AccountExpiredException;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.CredentialsExpiredException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.InsufficientAuthenticationException;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import static de.theit.jenkins.crowd.ErrorMessages.accountExpired;
import static de.theit.jenkins.crowd.ErrorMessages.applicationPermission;
import static de.theit.jenkins.crowd.ErrorMessages.expiredCredentials;
import static de.theit.jenkins.crowd.ErrorMessages.invalidAuthentication;
import static de.theit.jenkins.crowd.ErrorMessages.operationFailed;
import static de.theit.jenkins.crowd.ErrorMessages.userNotFound;
import static de.theit.jenkins.crowd.ErrorMessages.userNotValid;

/**
 * This class implements the authentication manager for Jenkins.
 * 
 * @author <a href="mailto:theit@gmx.de">Thorsten Heit (theit@gmx.de)</a>
 * @since 07.09.2011
 * @version $Id$
 */
public class CrowdAuthenticationManager implements AuthenticationManager {
	/** Used for logging purposes. */
	private static final Logger LOG = Logger
			.getLogger(CrowdAuthenticationManager.class.getName());

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
	public CrowdAuthenticationManager(CrowdConfigurationService pConfiguration) {
		this.configuration = pConfiguration;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @see org.acegisecurity.AuthenticationManager#authenticate(org.acegisecurity.Authentication)
	 */
	@Override
	public Authentication authenticate(Authentication authentication)
			throws AuthenticationException {
		String username = authentication.getPrincipal().toString();

		// checking whether there's already a SSO token
		if (null == authentication.getCredentials()
				&& authentication instanceof CrowdAuthenticationToken
				&& null != ((CrowdAuthenticationToken) authentication)
						.getSSOToken()) {
			// SSO token available => user already authenticated
			if (LOG.isLoggable(Level.FINER)) {
				LOG.finer("User '" + username + "' already authenticated");
			}
			return authentication;
		}

		String password = authentication.getCredentials().toString();

		// ensure that the group is available, active and that the user
		// is a member of it
		if (!this.configuration.isGroupMember(username)) {
			throw new InsufficientAuthenticationException(userNotValid(
				username, this.configuration.getAllowedGroupNames()));
		}

		//String displayName = null;
		try {
			// authenticate user
			if (LOG.isLoggable(Level.FINE)) {
				LOG.fine("Authenticating user: " + username);
			}
			User user = this.configuration.authenticateUser(
					username, password);
			CrowdAuthenticationToken.updateUserInfo(user);
			//displayName = user.getDisplayName();
		} catch (UserNotFoundException ex) {
			if (LOG.isLoggable(Level.INFO)) {
				LOG.info(userNotFound(username));
			}
			throw new BadCredentialsException(userNotFound(username), ex);
		} catch (ExpiredCredentialException ex) {
			LOG.warning(expiredCredentials(username));
			throw new CredentialsExpiredException(expiredCredentials(username),
					ex);
		} catch (InactiveAccountException ex) {
			LOG.warning(accountExpired(username));
			throw new AccountExpiredException(accountExpired(username), ex);
		} catch (ApplicationPermissionException ex) {
			LOG.warning(applicationPermission());
			throw new AuthenticationServiceException(applicationPermission(),
					ex);
		} catch (InvalidAuthenticationException ex) {
			LOG.warning(invalidAuthentication());
			throw new AuthenticationServiceException(invalidAuthentication(),
					ex);
		} catch (OperationFailedException ex) {
			LOG.log(Level.SEVERE, operationFailed(), ex);
			throw new AuthenticationServiceException(operationFailed(), ex);
		}

		// user successfully authenticated
		// => retrieve the list of groups the user is a member of
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();

		// add the "authenticated" authority to the list of granted
		// authorities...
		authorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
		// ..and finally all authorities retrieved from the Crowd server
		authorities.addAll(this.configuration.getAuthoritiesForUser(username));

		// user successfully authenticated => create authentication token
		if (LOG.isLoggable(Level.FINE)) {
			LOG.fine("User successfully authenticated; creating authentication token");
		}
	
		return new CrowdAuthenticationToken(username, password, authorities,null);
	}
	
	

}
