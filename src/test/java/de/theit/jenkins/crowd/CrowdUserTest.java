package de.theit.jenkins.crowd;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.atlassian.crowd.model.user.User;

import com.atlassian.crowd.model.user.UserTemplateWithAttributes;
import com.atlassian.crowd.model.user.UserWithAttributes;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;

import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.Test;

public class CrowdUserTest {

	private CrowdUser dummy;

	@Before
	public void setUp() {
		User user = new UserTemplateWithAttributes("user1", 0);
		List<GrantedAuthority> authorities = new ArrayList<>();
		authorities.add(new GrantedAuthorityImpl("fooGroup"));
		dummy = new CrowdUser(user, authorities);
	}

	@Test
	public void testCrowdUser() {

		Assertions.assertThat("user1").isEqualTo(dummy.getUsername());
		Assertions.assertThat("fooGroup").isEqualTo(dummy.getAuthorities()[0].getAuthority());
	}

	@Test
	public void testGetAuthorities() {
		Assertions.assertThat("fooGroup").isEqualTo(dummy.getAuthorities()[0].getAuthority());
	}

	@Test
	public void testGetPassword() {
		Assertions.assertThatThrownBy(() -> dummy.getPassword()).isInstanceOf(UnsupportedOperationException.class);
	}

	@Test
	public void testGetUsername() {
		Assertions.assertThat("user1").isEqualTo(dummy.getUsername());
	}

	@Test
	public void testIsAccountNonExpired() {
		// Always true. In Crowd accounts are enabled or disabled. No "expired" property available.
		Assertions.assertThat(dummy.isAccountNonExpired()).isTrue();
	}

	@Test
	public void testIsAccountNonLocked() {
		// Always true. In Crowd accounts are enabled or disabled. No "locked" property available.
		Assertions.assertThat(dummy.isAccountNonLocked()).isTrue();
	}

	@Test
	public void testIsCredentialsNonExpired() {
		// Always true. In Crowd accounts are enabled or disabled. No "credentials
		// expired" property available.
		Assertions.assertThat(dummy.isCredentialsNonExpired()).isTrue();
	}

/*	@Test
	public void testIsEnabled() {
		Assertions.assertThat(dummy.isEnabled()).isFalse();
		User user2 = new UserTemplateWithAttributes("user2", 1);
		CrowdUser u2 = new CrowdUser(user2, Collections.emptyList());
		Assertions.assertThat(u2.isEnabled()).isTrue();
	}
*/
/*	@Test
	public void testGetEmailAddress() {
		Assertions.assertThat("foo@bar.baz").isEqualTo(dummy.getEmailAddress());
	}
*/
}
