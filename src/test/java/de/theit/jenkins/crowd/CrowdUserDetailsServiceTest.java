package de.theit.jenkins.crowd;

import com.atlassian.crowd.exception.ApplicationPermissionException;
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.exception.UserNotFoundException;
import com.atlassian.crowd.model.user.ImmutableUser;

import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class CrowdUserDetailsServiceTest {

    private ImmutableUser user;

    @Before
    public void setUp() {
        user = new ImmutableUser(0, "foo", "foo bar", "foo.bar@baz.com", true, "foo", "bar", null);
    }

    @Test
    public void testCrowdUserDetailsService() {
        CrowdConfigurationService config = Mockito.mock(CrowdConfigurationService.class);
        CrowdUserDetailsService s = new CrowdUserDetailsService(config);
        Assertions.assertThatThrownBy(() -> s.loadUserByUsername("foo")).isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    public void testLoadUserByUsername() {
        CrowdConfigurationService config = Mockito.mock(CrowdConfigurationService.class);
        CrowdUserDetailsService s = new CrowdUserDetailsService(config);
        try {
            Mockito.when(config.getUser("foo")).thenReturn(user);
        } catch (UserNotFoundException | OperationFailedException | ApplicationPermissionException
                | InvalidAuthenticationException e) {
            e.printStackTrace();
        }
        Mockito.when(config.isGroupMember("foo")).thenReturn(Boolean.TRUE);

        try (MockedStatic<hudson.model.User> utilities = Mockito.mockStatic(hudson.model.User.class)) {
            utilities.when(() -> hudson.model.User.getById("foo", false))
              .thenReturn(null);

            s.loadUserByUsername("foo");
        }

        Mockito.verify(config).getAuthoritiesForUser("foo");
    }

    @Test
    public void testLoadUserByUsernameEx1() throws UserNotFoundException, OperationFailedException,
            ApplicationPermissionException, InvalidAuthenticationException {
        CrowdConfigurationService config = Mockito.mock(CrowdConfigurationService.class);
        CrowdUserDetailsService s = new CrowdUserDetailsService(config);
        Mockito.when(config.isGroupMember("foo")).thenReturn(Boolean.TRUE);
        Mockito.when(config.getUser("foo")).thenThrow(UserNotFoundException.class);
        Assertions.assertThatThrownBy(() -> s.loadUserByUsername("foo")).isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    public void testLoadUserByUsernameEx2() throws UserNotFoundException, OperationFailedException,
            ApplicationPermissionException, InvalidAuthenticationException {
        CrowdConfigurationService config = Mockito.mock(CrowdConfigurationService.class);
        CrowdUserDetailsService s = new CrowdUserDetailsService(config);
        Mockito.when(config.isGroupMember("foo")).thenReturn(Boolean.TRUE);
        Mockito.when(config.getUser("foo")).thenThrow(ApplicationPermissionException.class);
        Assertions.assertThatThrownBy(() -> s.loadUserByUsername("foo"))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    public void testLoadUserByUsernameEx3() throws UserNotFoundException, OperationFailedException,
            ApplicationPermissionException, InvalidAuthenticationException {
        CrowdConfigurationService config = Mockito.mock(CrowdConfigurationService.class);
        CrowdUserDetailsService s = new CrowdUserDetailsService(config);
        Mockito.when(config.isGroupMember("foo")).thenReturn(Boolean.TRUE);
        Mockito.when(config.getUser("foo")).thenThrow(InvalidAuthenticationException.class);
        Assertions.assertThatThrownBy(() -> s.loadUserByUsername("foo"))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    public void testLoadUserByUsernameEx4() throws UserNotFoundException, OperationFailedException,
            ApplicationPermissionException, InvalidAuthenticationException {
        CrowdConfigurationService config = Mockito.mock(CrowdConfigurationService.class);
        CrowdUserDetailsService s = new CrowdUserDetailsService(config);
        Mockito.when(config.isGroupMember("foo")).thenReturn(Boolean.TRUE);
        Mockito.when(config.getUser("foo")).thenThrow(OperationFailedException.class);
        Assertions.assertThatThrownBy(() -> s.loadUserByUsername("foo")).isInstanceOf(UsernameNotFoundException.class);
    }
}
