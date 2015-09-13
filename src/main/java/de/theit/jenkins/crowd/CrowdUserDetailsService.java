
package de.theit.jenkins.crowd;

import com.atlassian.crowd.exception.ApplicationPermissionException;
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.exception.UserNotFoundException;
import hudson.security.SecurityRealm;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataRetrievalFailureException;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static de.theit.jenkins.crowd.ErrorMessages.*;

/**
 * This class provides the service to load a user object from the remote Crowd
 * server.
 *
 * @author <a href="mailto:theit@gmx.de">Thorsten Heit (theit@gmx.de)</a>
 * @since 07.09.2011
 * @version $Id$
 */
public class CrowdUserDetailsService implements UserDetailsService {
    private static final Logger LOG =  LoggerFactory.getLogger(CrowdUserDetailsService.class);

    private final CrowdConfigurationService configuration;

    public CrowdUserDetailsService(CrowdConfigurationService configuration){
        this.configuration = configuration;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.acegisecurity.userdetails.UserDetailsService#loadUserByUsername(java.lang.String)
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {

        if (!configuration.allowedGroupNames.isEmpty()) {
            // check whether there's at least one active group the user is a member
            // of
            if (!configuration.isGroupMember(username)) {
                throw new DataRetrievalFailureException(userNotValid(username, configuration.allowedGroupNames));
            }
        }
        com.atlassian.crowd.model.user.User principal;
        try {
            // load the user object from the remote Crowd server
            LOG.debug("Loading user object from the remote Crowd server...");
            principal = configuration.crowdClient.getUser(username);
        } catch (UserNotFoundException ex) {
            LOG.debug(userNotFound(username));
            throw new UsernameNotFoundException(userNotFound(username), ex);
        } catch (ApplicationPermissionException ex) {
            LOG.warn(applicationPermission());
            throw new DataRetrievalFailureException(applicationPermission(), ex);
        } catch (InvalidAuthenticationException ex) {
            LOG.warn(invalidAuthentication());
            throw new DataRetrievalFailureException(invalidAuthentication(), ex);
        } catch (OperationFailedException ex) {
            LOG.error(operationFailed(), ex);
            throw new DataRetrievalFailureException(operationFailed(), ex);
        }

        LOG.info("adding authorities in CrowdUserDetailsService.loadUserByUsername");
		Collection<GrantedAuthority> authorities = configuration.getAuthoritiesForUser(username);
		authorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY);

        LOG.debug("Returning crowd user details {}, for principal {}", authorities, principal);
		return new CrowdUserDetails(principal, authorities);
    }


}
