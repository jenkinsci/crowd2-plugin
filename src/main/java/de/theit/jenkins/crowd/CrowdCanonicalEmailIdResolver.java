package de.theit.jenkins.crowd;

import hudson.Extension;
import hudson.model.Hudson;
import hudson.model.User;
import hudson.security.SecurityRealm;
import hudson.tasks.Mailer;
import org.acegisecurity.userdetails.UsernameNotFoundException;

import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Attempts to resolve an email address provided as the user ID into a local user or (if no local user exists) into
 * a valid remote Crowd server user. While the remote operation could be expensive it should be rare as users are
 * "cached" locally.
 *
 * @author jstiefel
 */
@Extension
public class CrowdCanonicalEmailIdResolver extends User.CanonicalIdResolver {

    private static final Logger LOG = Logger
            .getLogger(CrowdCanonicalEmailIdResolver.class.getName());

    /**
     * Used to match email addresses provided to {@link #resolveCanonicalId(String, java.util.Map)}
     */
    protected static final String EMAIL_REGEX = "^\\s*?(.+)@(.+?)\\s*$";

    /**
     * Resolves an email id using the {@link CrowdSecurityRealm} if necessary, otherwise returns a {@code null}.
     *
     * @param idOrFullName
     *          An email id that will be passed to  {@link CrowdSecurityRealm#loadUserByEmail(String)}
     * @return id Or {@code null} when not resolvable.
     */
    @Override
    public String resolveCanonicalId(String idOrFullName, Map<String, ?> context) {

        if (idOrFullName == null || !idOrFullName.matches(EMAIL_REGEX))
            return null;

        for (User user : User.getAll()) {
            Mailer.UserProperty property = user.getProperty(Mailer.UserProperty.class);
            if (property != null && idOrFullName.equalsIgnoreCase(property.getAddress())) {
                if (LOG.isLoggable(Level.FINE))
                    LOG.fine("Resolved '" + idOrFullName + "' into local user " + user.getId());
                return user.getId();
            }
        }

        SecurityRealm realm = Hudson.getInstance().getSecurityRealm();
        if (realm instanceof CrowdSecurityRealm) {

            CrowdSecurityRealm crowdRealm = (CrowdSecurityRealm)realm;
            CrowdUser userDetails;
            try {
                userDetails = (CrowdUser)crowdRealm.loadUserByEmail(idOrFullName);

            } catch (UsernameNotFoundException e) {
                LOG.warning("User id '" + idOrFullName + "' could not be resolved into a Crowd user");
                return null;
            }

            if (LOG.isLoggable(Level.INFO))
                LOG.info("Resolved '" + idOrFullName + "' into remote crowd user id '" + userDetails.getUsername() + "'");

            return userDetails.getUsername();
        }

        return null;
    }
}
