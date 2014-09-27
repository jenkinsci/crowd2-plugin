package de.theit.jenkins.crowd;

import com.atlassian.crowd.model.user.User;
import org.acegisecurity.GrantedAuthority;
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
    private static final long serialVersionUID = 3L;
	private final User principal;
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

	/**
     * {@inheritDoc}
     *
     * @see org.acegisecurity.userdetails.UserDetails#getAuthorities()
     */
    @Override
    public GrantedAuthority[] getAuthorities() {
        return (GrantedAuthority[]) authorities.toArray();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.acegisecurity.userdetails.UserDetails#getPassword()
     */
    @Override
    public String getPassword() {
        throw new UnsupportedOperationException("Not giving you the password");
    }

    @Override
    public String getUsername() {
        return principal.getName();
    }

    /**
     * {@inheritDoc}
     *
     * @see org.acegisecurity.userdetails.UserDetails#isAccountNonExpired()
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.acegisecurity.userdetails.UserDetails#isAccountNonLocked()
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.acegisecurity.userdetails.UserDetails#isCredentialsNonExpired()
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.acegisecurity.userdetails.UserDetails#isEnabled()
     */
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
