package de.theit.jenkins.crowd;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.atlassian.crowd.model.user.ImmutableUser;

class CrowdUserTest {

	private CrowdUser dummy;

	@BeforeEach
	void setUp() {
		ImmutableUser u = new ImmutableUser(0, "user1", "foo user 1", "foo@bar.baz", false, null, null, null);
		List<GrantedAuthority> authorities = new ArrayList<>();
		authorities.add(new GrantedAuthorityImpl("fooGroup"));
		dummy = new CrowdUser(u, authorities);
	}

	@Test
	void testCrowdUser() {
		
		Assertions.assertEquals("user1", dummy.getUsername());
		Assertions.assertEquals("fooGroup", dummy.getAuthorities()[0].getAuthority());
	}

	@Test
	void testGetAuthorities() {
		Assertions.assertEquals("fooGroup", dummy.getAuthorities()[0].getAuthority());
	}

	@Test
	void testGetPassword() {
		Assertions.assertThrows(UnsupportedOperationException.class, ()->{
			dummy.getPassword();
		});
	}

	@Test
	void testGetUsername() {
		Assertions.assertEquals("user1", dummy.getUsername());
	}

	@Test
	void testIsAccountNonExpired() {
		// Always true. In Crowd accounts are enabled or disabled. No "expired" property available.
		Assertions.assertTrue(dummy.isAccountNonExpired());
	}

	@Test
	void testIsAccountNonLocked() {
		// Always true. In Crowd accounts are enabled or disabled. No "locked" property available.
		Assertions.assertTrue(dummy.isAccountNonLocked());
	}

	@Test
	void testIsCredentialsNonExpired() {
		// Always true. In Crowd accounts are enabled or disabled. No "credentials
		// expired" property available.
		Assertions.assertTrue(dummy.isCredentialsNonExpired());
	}

	@Test
	void testIsEnabled() {
		Assertions.assertFalse(dummy.isEnabled());
		ImmutableUser dummy2 = new ImmutableUser(1, "user2", "foo user 2", null, true, null, null, null);
		CrowdUser u2 = new CrowdUser(dummy2, Collections.emptyList());
		Assertions.assertTrue(u2.isEnabled());
	}

	@Test
	void testGetEmailAddress() {
		Assertions.assertEquals("foo@bar.baz", dummy.getEmailAddress());
	}

}
