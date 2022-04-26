/*
 * @(#)CrowdUserDetailsService.java
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
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.exception.UserNotFoundException;
import com.atlassian.crowd.model.user.User;

import hudson.security.SecurityRealm;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import static de.theit.jenkins.crowd.ErrorMessages.applicationPermission;
import static de.theit.jenkins.crowd.ErrorMessages.invalidAuthentication;
import static de.theit.jenkins.crowd.ErrorMessages.operationFailed;
import static de.theit.jenkins.crowd.ErrorMessages.userNotFound;
import static de.theit.jenkins.crowd.ErrorMessages.userNotValid;

/**
 * This class provides the service to load a user object from the remote Crowd
 * server.
 *
 * @author <a href="mailto:theit@gmx.de">Thorsten Heit (theit@gmx.de)</a>
 * @since 07.09.2011
 * @version $Id$
 */
public class CrowdUserDetailsService implements UserDetailsService {
    /** Used for logging purposes. */
    private static final Logger LOG = Logger
            .getLogger(CrowdUserDetailsService.class.getName());

    /**
     * The configuration data necessary for accessing the services on the remote
     * Crowd server.
     */
    private CrowdConfigurationService configuration;

    /**
     * Creates a new instance of this class.
     *
     * @param pConfiguration The configuration to access the services on the remote
     *                       Crowd server. May not be <code>null</code>.
     */
    public CrowdUserDetailsService(CrowdConfigurationService pConfiguration) {
        this.configuration = pConfiguration;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.springframework.security.core.userdetails.UserDetailsService#loadUserByUsername(java.lang.String)
     */
    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {

        // check whether there's at least one active group the user is a member
        // of
        if (!this.configuration.isGroupMember(username)) {
            throw new UsernameNotFoundException(userNotValid(username, this.configuration.getAllowedGroupNames()));
        }
        User user;
        try {
            // load the user object from the remote Crowd server
            if (LOG.isLoggable(Level.FINE)) {
                LOG.fine("Loading user object from the remote Crowd server...");
            }
            user = this.configuration.getUser(username);
        } catch (UserNotFoundException ex) {
            if (LOG.isLoggable(Level.INFO)) {
                LOG.info(userNotFound(username));
            }
            throw new UsernameNotFoundException(userNotFound(username), ex);
        } catch (ApplicationPermissionException ex) {
            LOG.warning(applicationPermission());
            throw new UsernameNotFoundException(applicationPermission(), ex);
        } catch (InvalidAuthenticationException ex) {
            LOG.warning(invalidAuthentication());
            throw new UsernameNotFoundException(invalidAuthentication(), ex);
        } catch (OperationFailedException ex) {
            LOG.log(Level.SEVERE, operationFailed(), ex);
            throw new UsernameNotFoundException(operationFailed(), ex);
        }

        // create the list of granted authorities
        List<GrantedAuthority> authorities = new ArrayList<>();
        // add the "authenticated" authority to the list of granted
        // authorities...
        authorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY2);
        // ..and all authorities retrieved from the Crowd server
        authorities.addAll(this.configuration.getAuthoritiesForUser(username));

        return new CrowdUser(user, authorities);
    }
}
