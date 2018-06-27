package de.theit.jenkins.crowd;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import hudson.model.User;
import hudson.security.SecurityRealm;

class CrowdMailAddressResolverImplTest {

	@Test
	void testGetUserIdFromDisplayName() {
		CrowdMailAddressResolverImpl res = new CrowdMailAddressResolverImpl();
		User user = Mockito.mock(User.class);
		Mockito.when(user.getId()).thenReturn("Foo Bar (baz)");
		String userIdFromDisplayName1 = res.getUserIdFromDisplayName(user);
		Assertions.assertEquals("baz", userIdFromDisplayName1);
		
		//should also work with arbitrary brackets in the username
		Mockito.when(user.getId()).thenReturn("Foo) (Bar) :) (zap)");
		String userIdFromDisplayName2 = res.getUserIdFromDisplayName(user);
		Assertions.assertEquals("zap", userIdFromDisplayName2);
	}
	
	@Test
	void testGetSecurityRealm() {
		CrowdSecurityRealm r = Mockito.mock(CrowdSecurityRealm.class);
		CrowdMailAddressResolverImpl res = new CrowdMailAddressResolverImpl() {
			protected SecurityRealm getSecurityRealm() {
				return r;
			}
		};
		Assertions.assertSame(r, res.getSecurityRealm());
	}

	@Test
	void testFindMailAddressForUser() {
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
		
		Assertions.assertEquals("foo@bar.baz", res.findMailAddressFor(user));
	}

}
