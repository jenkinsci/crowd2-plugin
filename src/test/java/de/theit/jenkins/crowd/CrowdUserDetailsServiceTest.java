package de.theit.jenkins.crowd;


import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.assertj.core.api.Assertions;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.dao.DataRetrievalFailureException;

import com.atlassian.crowd.exception.ApplicationPermissionException;
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.exception.UserNotFoundException;

public class CrowdUserDetailsServiceTest {

	@Test
	public void testCrowdUserDetailsService() {
		CrowdConfigurationService config = Mockito.mock(CrowdConfigurationService.class);
		CrowdUserDetailsService s = new CrowdUserDetailsService(config);
		Assertions.assertThatThrownBy(() -> s.loadUserByUsername("foo")).isInstanceOf(DataRetrievalFailureException.class);

	}

	@Test
	public void testLoadUserByUsername() {
		CrowdConfigurationService config = Mockito.mock(CrowdConfigurationService.class);
		CrowdUserDetailsService s = new CrowdUserDetailsService(config);
		Mockito.when(config.isGroupMember("foo")).thenReturn(Boolean.TRUE);
		s.loadUserByUsername("foo");
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
		Assertions.assertThatThrownBy(() -> s.loadUserByUsername("foo")).isInstanceOf(DataRetrievalFailureException.class);
	}

	@Test
	public void testLoadUserByUsernameEx3() throws UserNotFoundException, OperationFailedException,
			ApplicationPermissionException, InvalidAuthenticationException {
		CrowdConfigurationService config = Mockito.mock(CrowdConfigurationService.class);
		CrowdUserDetailsService s = new CrowdUserDetailsService(config);
		Mockito.when(config.isGroupMember("foo")).thenReturn(Boolean.TRUE);
		Mockito.when(config.getUser("foo")).thenThrow(InvalidAuthenticationException.class);
		Assertions.assertThatThrownBy(() -> s.loadUserByUsername("foo")).isInstanceOf(DataRetrievalFailureException.class);
	}

	@Test
	public void testLoadUserByUsernameEx4() throws UserNotFoundException, OperationFailedException,
			ApplicationPermissionException, InvalidAuthenticationException {
		CrowdConfigurationService config = Mockito.mock(CrowdConfigurationService.class);
		CrowdUserDetailsService s = new CrowdUserDetailsService(config);
		Mockito.when(config.isGroupMember("foo")).thenReturn(Boolean.TRUE);
		Mockito.when(config.getUser("foo")).thenThrow(OperationFailedException.class);
		Assertions.assertThatThrownBy(() -> s.loadUserByUsername("foo")).isInstanceOf(DataRetrievalFailureException.class);
	}
}
