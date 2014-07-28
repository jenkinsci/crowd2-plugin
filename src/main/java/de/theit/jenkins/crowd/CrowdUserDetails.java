package de.theit.jenkins.crowd;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;

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
    private final String externalId;
    private String password;
    private String username;
    private boolean active;
    private GrantedAuthority[] authorities;

    private final String firstName;
    private final String lastName;
    private final long directoryId;
    private final String email;
    /** Holds the Crowd user object. */
    private transient com.atlassian.crowd.model.user.User crowdUser;

    /**
     * Creates a new instance.
     *
     * @param crowdUser
     *            Crowd user object. May not be <code>null</code>.
     * @param authorities
     *            The granted authorities of the user. May not be
     *            <code>null</code>.
     */
    public CrowdUserDetails(String username, String password, boolean active,
                            String externalId, String firstName,
                            String lastName, long directoryId,
                            GrantedAuthority[] authorities,
                            String email,
                            com.atlassian.crowd.model.user.User crowdUser)
            throws IllegalArgumentException {
        this.active = active;
        this.externalId = externalId;
        this.username = username;
        this.password = password;
        this.firstName = firstName;
        this.lastName = lastName;
        this.directoryId = directoryId;
        this.authorities = authorities;
        this.email = email;
        //temp
        this.crowdUser = crowdUser;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.acegisecurity.userdetails.UserDetails#getAuthorities()
     */
    @Override
    public GrantedAuthority[] getAuthorities() {
        return authorities;
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
        return username;
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
        return active;
    }

    public String getExternalId() {
        return externalId;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public long getDirectoryId() {
        return directoryId;
    }

    public String getEmailAddress() {
        return email;
    }

}
