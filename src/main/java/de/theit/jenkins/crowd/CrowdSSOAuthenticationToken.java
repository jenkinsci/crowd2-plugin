/*
 * @(#)CrowdAuthenticationToken.java
 * 
 * The MIT License
 * 
 * Copyright (C)2011 Thorsten Heit.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package de.theit.jenkins.crowd;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.AbstractAuthenticationToken;

/**
 * initially was used for storing either Username+Password either Crowd token?
 */
public class CrowdSSOAuthenticationToken extends AbstractAuthenticationToken {
	private static final String UNAUTHENTICATED_TOKEN_PRINCIPAL = "CROWD.SSO";
	private Object credentials;
	private Object principal;

	public CrowdSSOAuthenticationToken(String ssoToken) {
		super(null);
		this.principal = UNAUTHENTICATED_TOKEN_PRINCIPAL;
		this.credentials = ssoToken;
		setAuthenticated(false);
	}

	public CrowdSSOAuthenticationToken(CrowdUserDetails principal, String ssoToken, GrantedAuthority[] authorities)	{
		super(authorities);
		this.principal = principal;
		this.credentials = ssoToken;
		super.setAuthenticated(true);
	}

	public Object getCredentials() {
		return this.credentials;
	}

	public Object getPrincipal() {
		return this.principal;
	}

	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		if (isAuthenticated) {
			throw new IllegalArgumentException("Cannot set this token to trusted - use constructor containing GrantedAuthority[]s instead");
		} else {
			super.setAuthenticated(false);
		}
	}
}
