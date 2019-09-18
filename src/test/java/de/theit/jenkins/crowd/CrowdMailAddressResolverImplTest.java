package de.theit.jenkins.crowd;

import hudson.model.User;
import hudson.security.SecurityRealm;
import org.assertj.core.api.Assertions;
import org.junit.Test;
import org.mockito.Mockito;

public class CrowdMailAddressResolverImplTest {

	@Test
	public void testGetUserIdFromDisplayName() {
		CrowdMailAddressResolverImpl res = new CrowdMailAddressResolverImpl();
		User user = Mockito.mock(User.class);
		Mockito.when(user.getId()).thenReturn("Foo Bar (baz)");
		String userIdFromDisplayName1 = res.getUserIdFromDisplayName(user);
		Assertions.assertThat("baz").isEqualTo(userIdFromDisplayName1);

		//should also work with arbitrary brackets in the username
		Mockito.when(user.getId()).thenReturn("Foo) (Bar) :) (zap)");
		String userIdFromDisplayName2 = res.getUserIdFromDisplayName(user);
		Assertions.assertThat("zap").isEqualTo(userIdFromDisplayName2);
	}

	@Test
	public void testGetSecurityRealm() {
		CrowdSecurityRealm r = Mockito.mock(CrowdSecurityRealm.class);
		CrowdMailAddressResolverImpl res = new CrowdMailAddressResolverImpl() {
			protected SecurityRealm getSecurityRealm() {
				return r;
			}
		};
		Assertions.assertThat(r).isSameAs(res.getSecurityRealm());
	}

	@Test
	public void testFindMailAddressForUser() {
		CrowdSecurityRealm r = Mockito.mock(CrowdSecurityRealm.class);
		CrowdMailAddressResolverImpl res = new CrowdMailAddressResolverImpl() {
			protected SecurityRealm getSecurityRealm() {
				return r;
			}
		};

		CrowdUser crowdUser = Mockito.mock(CrowdUser.class);
		Mockito.when(crowdUser.getEmailAddress()).thenReturn("foo@bar.baz");
		Mockito.when(r.loadUserByUsername("foo")).thenReturn(crowdUser);
		User user = Mockito.mock(User.class);
		Mockito.when(user.getId()).thenReturn("Firstname Lastname (foo)");

		Assertions.assertThat("foo@bar.baz").isEqualTo(res.findMailAddressFor(user));
	}

}
