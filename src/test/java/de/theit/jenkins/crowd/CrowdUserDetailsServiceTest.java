package de.theit.jenkins.crowd;

import static org.junit.jupiter.api.Assertions.*;

import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.dao.DataRetrievalFailureException;

import com.atlassian.crowd.exception.ApplicationPermissionException;
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.exception.UserNotFoundException;

class CrowdUserDetailsServiceTest {

	@Test
	void testCrowdUserDetailsService() {
		CrowdConfigurationService config = Mockito.mock(CrowdConfigurationService.class);
		CrowdUserDetailsService s = new CrowdUserDetailsService(config);
		assertThrows(DataRetrievalFailureException.class, () -> s.loadUserByUsername("foo"));

	}

	@Test
	void testLoadUserByUsername() {
		CrowdConfigurationService config = Mockito.mock(CrowdConfigurationService.class);
		CrowdUserDetailsService s = new CrowdUserDetailsService(config);
		Mockito.when(config.isGroupMember("foo")).thenReturn(Boolean.TRUE);
		s.loadUserByUsername("foo");
		Mockito.verify(config).getAuthoritiesForUser("foo");
	}

	@Test
	void testLoadUserByUsernameEx1() throws UserNotFoundException, OperationFailedException,
			ApplicationPermissionException, InvalidAuthenticationException {
		CrowdConfigurationService config = Mockito.mock(CrowdConfigurationService.class);
		CrowdUserDetailsService s = new CrowdUserDetailsService(config);
		Mockito.when(config.isGroupMember("foo")).thenReturn(Boolean.TRUE);
		Mockito.when(config.getUser("foo")).thenThrow(UserNotFoundException.class);
		assertThrows(UsernameNotFoundException.class, () -> s.loadUserByUsername("foo"));
	}

	@Test
	void testLoadUserByUsernameEx2() throws UserNotFoundException, OperationFailedException,
			ApplicationPermissionException, InvalidAuthenticationException {
		CrowdConfigurationService config = Mockito.mock(CrowdConfigurationService.class);
		CrowdUserDetailsService s = new CrowdUserDetailsService(config);
		Mockito.when(config.isGroupMember("foo")).thenReturn(Boolean.TRUE);
		Mockito.when(config.getUser("foo")).thenThrow(ApplicationPermissionException.class);
		assertThrows(DataRetrievalFailureException.class, () -> s.loadUserByUsername("foo"));
	}

	@Test
	void testLoadUserByUsernameEx3() throws UserNotFoundException, OperationFailedException,
			ApplicationPermissionException, InvalidAuthenticationException {
		CrowdConfigurationService config = Mockito.mock(CrowdConfigurationService.class);
		CrowdUserDetailsService s = new CrowdUserDetailsService(config);
		Mockito.when(config.isGroupMember("foo")).thenReturn(Boolean.TRUE);
		Mockito.when(config.getUser("foo")).thenThrow(InvalidAuthenticationException.class);
		assertThrows(DataRetrievalFailureException.class, () -> s.loadUserByUsername("foo"));
	}

	@Test
	void testLoadUserByUsernameEx4() throws UserNotFoundException, OperationFailedException,
			ApplicationPermissionException, InvalidAuthenticationException {
		CrowdConfigurationService config = Mockito.mock(CrowdConfigurationService.class);
		CrowdUserDetailsService s = new CrowdUserDetailsService(config);
		Mockito.when(config.isGroupMember("foo")).thenReturn(Boolean.TRUE);
		Mockito.when(config.getUser("foo")).thenThrow(OperationFailedException.class);
		assertThrows(DataRetrievalFailureException.class, () -> s.loadUserByUsername("foo"));
	}
}
