package de.theit.jenkins.crowd;

import com.atlassian.crowd.model.user.User;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.userdetails.UserDetails;

import java.util.Arrays;
import java.util.Collection;

/**
 * This class provides the information about a user that was authenticated
 * successfully against a remote Crowd server.
 *
 * @author <a href="mailto:theit@gmx.de">Thorsten Heit (theit@gmx.de)</a>
 * @since 07.09.2011
 * @version $Id$
 */
public class CrowdUserDetails implements UserDetails {
    /** Necessary for serialisation. */
//    private static final long serialVersionUID = -907996070755427898L;
// wow, seems it was mistake to change it
    private static final long serialVersionUID = 3L;

    private final User principal;
    /**
     * like in spring security store it in Collection instead array.
     * Acegi needs array and TreeSet.toArray fails.
     * TODO migrate to GrantedAuthorityImpl instead GrantedAuthority?
     */
    private final Collection<GrantedAuthority> authorities;

    /**
     * Creates a new instance.
     *
     * @param principal
     *            Crowd user object. May not be <code>null</code>.
     * @param authorities
     *            The granted authorities of the user. May not be
     *            <code>null</code>.
     */
    public CrowdUserDetails(User principal, GrantedAuthority[] authorities){
        this.principal = principal;
        this.authorities = Arrays.asList(authorities);
    }

    public CrowdUserDetails(User principal, Collection<GrantedAuthority> authorities){
        this.principal = principal;
        this.authorities = authorities;
    }

    @Override
    public GrantedAuthority[] getAuthorities() {
        // when authorities is TreeSet, toArray GA[] fails
        return authorities.toArray(new GrantedAuthorityImpl[authorities.size()]);
    }

    @Override
    public String getPassword() {
        throw new UnsupportedOperationException("Not giving you the password");
    }

    @Override
    public String getUsername() {
        return principal.getName();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return principal.isActive();
    }

    public String getExternalId() {
        return principal.getExternalId();
    }

    public String getFirstName() {
        return principal.getFirstName();
    }

    public String getLastName() {
        return principal.getLastName();
    }

    public long getDirectoryId() {
        return principal.getDirectoryId();
    }

    public String getEmailAddress() {
        return principal.getEmailAddress();
    }
}
