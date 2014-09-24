/**
 The MIT License (MIT)

 Copyright (c) <2014> <Kanstantsin Shautsou>

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE

 */
package de.theit.jenkins.crowd;

import com.atlassian.crowd.exception.*;
import com.atlassian.crowd.model.user.User;
import hudson.security.SecurityRealm;
import org.acegisecurity.*;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.AbstractAuthenticationToken;
import org.acegisecurity.providers.AuthenticationProvider;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;

import java.util.ArrayList;
import java.util.List;

import static de.theit.jenkins.crowd.ErrorMessages.*;

/**
 *
 */
public class CrowdAuthenticationProvider implements AuthenticationProvider, InitializingBean {
    private static final Log LOG = LogFactory.getLog(CrowdAuthenticationProvider.class);

	CrowdConfigurationService configuration;

	public CrowdAuthenticationProvider(CrowdConfigurationService configuration){
		this.configuration = configuration;
	}

    public void afterPropertiesSet() throws Exception {
        LOG.info("CrowdAuthenticationProvider.afterPropertiesSet()");
//        Assert.hasLength(key, "A Key is required");
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }

		if (!supports((AbstractAuthenticationToken)authentication))
		{
			return null;
		}


		if (authentication instanceof UsernamePasswordAuthenticationToken){
			LOG.info("instanceof UsernamePasswordAuthenticationToken");
		} else if (authentication instanceof CrowdSSOAuthenticationToken){
			LOG.info("instanceof CrowdAuthenticationToken");
		}

		String username = authentication.getPrincipal().toString();

		// checking whether there's already a SSO token
		if (null == authentication.getCredentials()
				&& authentication instanceof CrowdSSOAuthenticationToken
				&& null != ((CrowdSSOAuthenticationToken) authentication).getSSOToken()) {
			// SSO token available => user already authenticated
			LOG.info("User '" + username + "' already authenticated");
			return authentication;
		}

		String password = null;
		try {
			Object cred = authentication.getCredentials();
			if (cred != null) {
				password = cred.toString();
				LOG.info("password is not null");
			}
			// authenticate user
			LOG.info("Authenticating user: " + username);
			User user = configuration.crowdClient.authenticateUser(username, password);
			final String displayName = user == null ? null :  user.getDisplayName();
			if(StringUtils.isNotBlank(displayName) && user != null) {
				final String usernamee = user.getName();
				hudson.model.User.get(usernamee).setFullName(displayName + " (" + usernamee+ ')');
			}
		} catch (UserNotFoundException ex) {
			LOG.info(userNotFound(username));
			throw new BadCredentialsException(userNotFound(username), ex);
		} catch (ExpiredCredentialException ex) {
			LOG.warn(expiredCredentials(username));
			throw new CredentialsExpiredException(expiredCredentials(username),	ex);
		} catch (InactiveAccountException ex) {
			LOG.warn(accountExpired(username));
			throw new AccountExpiredException(accountExpired(username), ex);
		} catch (ApplicationPermissionException ex) {
			LOG.warn(applicationPermission());
			throw new AuthenticationServiceException(applicationPermission(), ex);
		} catch (InvalidAuthenticationException ex) {
			LOG.warn(invalidAuthentication());
			throw new AuthenticationServiceException(invalidAuthentication(), ex);
		} catch (OperationFailedException ex) {
			LOG.error(operationFailed(), ex);
			throw new AuthenticationServiceException(operationFailed(), ex);
		}

		if (!configuration.allowedGroupNames.isEmpty()) {
			// ensure that the group is available, active and that the user is a member of it
			if (!configuration.isGroupMember(username)) {
				throw new InsufficientAuthenticationException(userNotValid(username, configuration.allowedGroupNames));
			}
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
		LOG.info("User successfully authenticated; creating authentication token");
//		CrowdAuthenticationToken token;
//		if (configuration.useSSO){
//			//TODO
////			configuration.clientProperties.getApplicationAuthenticationContext()
//			token = new CrowdAuthenticationToken(username, password, authorities, null);
//		} else {
//			token = new CrowdAuthenticationToken(username, password, authorities, null);
//		}
		authentication.set
		token.setAuthenticated(true);
		SecurityContextHolder.getContext().setAuthentication(token);
		return token;
    }

//    @Override
//    public boolean supports(Class authentication) {
//		return CrowdAuthenticationToken.class.isAssignableFrom(authentication) || UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
//    }

	@Override
	public boolean supports(AbstractAuthenticationToken authenticationToken)
	{
		if ((authenticationToken.getDetails() == null) || (!(authenticationToken.getDetails() instanceof CrowdSSOAuthenticationDetails)))
		{
			return true;
		}
		if ((authenticationToken.getDetails() instanceof CrowdSSOAuthenticationDetails))
		{
			CrowdSSOAuthenticationDetails details = (CrowdSSOAuthenticationDetails)authenticationToken.getDetails();
			return details.getApplicationName().equals(this.applicationName);
		}

		return false;
	}
}
