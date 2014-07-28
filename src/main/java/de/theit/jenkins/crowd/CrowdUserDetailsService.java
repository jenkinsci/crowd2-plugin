
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
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataRetrievalFailureException;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

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
    private static final Logger LOG =  Logger.getLogger(CrowdUserDetailsService.class.getName());
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
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException, DataAccessException {

        if (!configuration.allowedGroupNames.isEmpty()) {
            // check whether there's at least one active group the user is a member
            // of
            if (!configuration.isGroupMember(username)) {
                throw new DataRetrievalFailureException(userNotValid(username, configuration.allowedGroupNames));
            }
        }
        com.atlassian.crowd.model.user.User crowdUser;
        try {
            // load the user object from the remote Crowd server
            if (LOG.isLoggable(Level.FINE)) {
                LOG.fine("Loading user object from the remote Crowd server...");
            }
            crowdUser = configuration.crowdClient.getUser(username);
        } catch (UserNotFoundException ex) {
            if (LOG.isLoggable(Level.INFO)) {
                LOG.info(userNotFound(username));
            }
            throw new UsernameNotFoundException(userNotFound(username), ex);
        } catch (ApplicationPermissionException ex) {
            LOG.warning(applicationPermission());
            throw new DataRetrievalFailureException(applicationPermission(), ex);
        } catch (InvalidAuthenticationException ex) {
            LOG.warning(invalidAuthentication());
            throw new DataRetrievalFailureException(invalidAuthentication(), ex);
        } catch (OperationFailedException ex) {
            LOG.log(Level.SEVERE, operationFailed(), ex);
            throw new DataRetrievalFailureException(operationFailed(), ex);
        }

        // create the list of granted authorities
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        // add the "authenticated" authority to the list of granted
        // authorities...
        LOG.info("adding authorities in CrowdUserDetailsService.loadUserByUsername");
        authorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
        // ..and all authorities retrieved from the Crowd server
        authorities.addAll(configuration.getAuthoritiesForUser(username));

        return new CrowdUserDetails(username,
                null,        // no password here
                crowdUser.isActive(),
                crowdUser.getExternalId(),
                crowdUser.getFirstName(),
                crowdUser.getLastName(),
                crowdUser.getDirectoryId(),
                authorities.toArray(new GrantedAuthority[authorities.size()]),
                crowdUser.getEmailAddress(),
                crowdUser
        );
    }


}
