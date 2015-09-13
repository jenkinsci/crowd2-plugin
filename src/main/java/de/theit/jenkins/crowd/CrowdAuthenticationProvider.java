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

import com.atlassian.crowd.exception.ApplicationAccessDeniedException;
import com.atlassian.crowd.exception.ApplicationPermissionException;
import com.atlassian.crowd.exception.ExpiredCredentialException;
import com.atlassian.crowd.exception.InactiveAccountException;
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.InvalidAuthorizationTokenException;
import com.atlassian.crowd.exception.InvalidTokenException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.exception.UserNotFoundException;
import com.atlassian.crowd.model.authentication.ValidationFactor;
import com.atlassian.crowd.model.user.User;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.CredentialsExpiredException;
import org.acegisecurity.DisabledException;
import org.acegisecurity.providers.AbstractAuthenticationToken;
import org.acegisecurity.providers.AuthenticationProvider;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;

import java.rmi.RemoteException;

/**
 *
 */
public class CrowdAuthenticationProvider implements AuthenticationProvider {
    private static final Logger LOG = LoggerFactory.getLogger(CrowdAuthenticationProvider.class);

    private CrowdConfigurationService configuration;

    public CrowdAuthenticationProvider(CrowdConfigurationService configuration){
        this.configuration = configuration;
    }

    /**
     * extract credentials to get group & authorities,
     * then return authenticated token.
     * Supports UsernamePasswordAuthenticationToken or CrowdSSOAuthenticationToken.
     * UserDetails as principal for working RememberMe.
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        //check that we can work with this type of Authentication
        if (!supports(authentication.getClass())) {
            return null;
        }

        if (!supports((AbstractAuthenticationToken) authentication)) {
            return null;
        }

        Authentication authenticatedToken = null;

        if ((authentication instanceof UsernamePasswordAuthenticationToken)) {
            LOG.debug("Processing a UsernamePasswordAuthenticationToken: ", authentication);
            authenticatedToken = authenticateUsernamePassword((UsernamePasswordAuthenticationToken) authentication);
        } else if ((authentication instanceof CrowdSSOAuthenticationToken)) {
            LOG.debug("Processing a CrowdSSOAuthenticationToken");
            authenticatedToken = authenticateCrowdSSO((CrowdSSOAuthenticationToken) authentication);
        }

        return authenticatedToken;
    }

    /**
     * Auth User/Password login from UsernamePasswordAuthenticationToken.class
     */
    protected Authentication authenticateUsernamePassword(UsernamePasswordAuthenticationToken passwordToken)
            throws AuthenticationException {
        if (StringUtils.isEmpty((String) passwordToken.getPrincipal())) {
            throw new BadCredentialsException("UsernamePasswordAuthenticationToken contains empty username");
        }

        if (StringUtils.isEmpty((String) passwordToken.getCredentials())) {
            throw new BadCredentialsException("UsernamePasswordAuthenticationToken contains empty password");
        }

        Authentication authenticatedToken;
        try {
            if (passwordToken.getDetails() instanceof CrowdSSOAuthenticationDetails) {
                CrowdSSOAuthenticationDetails details = (CrowdSSOAuthenticationDetails) passwordToken.getDetails();

                //TODO bad call to get token, it null atm
                String crowdToken = authenticateUsernamePassword(passwordToken.getPrincipal().toString(),
                        passwordToken.getCredentials().toString(),
                        details.getValidationFactors()
                );
                CrowdUserDetails userDetails = loadUserByUsername(passwordToken.getPrincipal().toString());
                authenticatedToken = new CrowdSSOAuthenticationToken(userDetails, crowdToken, userDetails.getAuthorities());
            } else {
                // user/pass is stored in incomeing WebAuthDetails
                authenticateUsernamePassword(passwordToken.getPrincipal().toString(),
                        passwordToken.getCredentials().toString(),
                        new ValidationFactor[0]
                );
                CrowdUserDetails userDetails = loadUserByUsername((String) passwordToken.getPrincipal());
                authenticatedToken = new UsernamePasswordAuthenticationToken(userDetails,
                        passwordToken.getCredentials(),
                        userDetails.getAuthorities()
                );
            }
        } catch (Exception e) {
            LOG.error("Can't authenticate token {}", passwordToken, e);
            throw translateException(e);
        }

        return authenticatedToken;
    }

    /**
     * Auth Crowd SSO
     */
    protected Authentication authenticateCrowdSSO(CrowdSSOAuthenticationToken ssoToken) throws AuthenticationException {
        if ((ssoToken.getCredentials() == null) || (StringUtils.isEmpty(ssoToken.getCredentials().toString())))	{
            throw new BadCredentialsException("CrowdSSOAuthenticationToken contains empty token credential");
        }

        if ((ssoToken.getDetails() == null) || (!(ssoToken.getDetails() instanceof CrowdSSOAuthenticationDetails)))	{
            throw new BadCredentialsException("CrowdSSOAuthenticationToken does not contain any validation factors");
        }

        Authentication authenticatedToken;
        String crowdToken = ssoToken.getCredentials().toString();
        CrowdSSOAuthenticationDetails details = (CrowdSSOAuthenticationDetails)ssoToken.getDetails();
        try {
            configuration.crowdClient.validateSSOAuthentication(crowdToken, details.getValidationFactorsList());
            CrowdUserDetails userDetails = loadUserByToken(crowdToken);
            authenticatedToken = new CrowdSSOAuthenticationToken(userDetails, crowdToken, userDetails.getAuthorities());
        } catch (Exception e) {
            LOG.error("Can't authenticate token", e);
            throw translateException(e);
        }

        return authenticatedToken;
    }

    /**
     * Where it required?
     * TODO Wouldn't work as SSO routine calls it to get token.
     */
    protected String authenticateUsernamePassword(String username, String password, ValidationFactor[] validationFactors)
            throws InvalidAuthorizationTokenException, InvalidAuthenticationException, RemoteException, InactiveAccountException, ApplicationAccessDeniedException, ExpiredCredentialException, UserNotFoundException, OperationFailedException, ApplicationPermissionException {
        configuration.crowdClient.authenticateUser(username, password);
        return null;
    }

    protected CrowdUserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException, DataAccessException {
        return (CrowdUserDetails) Jenkins.getInstance().getSecurityRealm().loadUserByUsername(username);
    }

    protected CrowdUserDetails loadUserByToken(String token)
            throws CrowdSSOTokenInvalidException, DataAccessException, ApplicationPermissionException,
            InvalidTokenException, OperationFailedException, InvalidAuthenticationException {
        User userFromSSOToken = configuration.crowdClient.findUserFromSSOToken(token);
        return loadUserByUsername(userFromSSOToken.getName());
    }

    protected AuthenticationException translateException(Exception e) {
        if ((e instanceof AuthenticationException)) {
            return (AuthenticationException) e;
        }

        if ((e instanceof ApplicationAccessDeniedException)) {
            return new CrowdAccessDeniedException("User does not have access to application: ");
        }

        if ((e instanceof ExpiredCredentialException)) {
            return new CredentialsExpiredException(e.getMessage());
        }

        if (((e instanceof InvalidAuthenticationException)) || ((e instanceof InvalidTokenException))) {
            return new BadCredentialsException(e.getMessage(), e);
        }

        if ((e instanceof InactiveAccountException)) {
            return new DisabledException(e.getMessage(), e);
        }

        return new AuthenticationServiceException(e.getMessage(), e);
    }

    /**
     * whether this provider support requested Class
     */
    @Override
    public boolean supports(Class authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication))
                || (CrowdSSOAuthenticationToken.class.isAssignableFrom(authentication));
    }

    /**
     * Whether this provider support this type of token
     */
    public boolean supports(AbstractAuthenticationToken authenticationToken) {
        if (authenticationToken.getDetails() instanceof CrowdSSOAuthenticationDetails) {
            CrowdSSOAuthenticationDetails details = (CrowdSSOAuthenticationDetails) authenticationToken.getDetails();
            return details.getApplicationName().equals(configuration.clientProperties.getApplicationName());
        } else {
            return true;
        }
    }
}
