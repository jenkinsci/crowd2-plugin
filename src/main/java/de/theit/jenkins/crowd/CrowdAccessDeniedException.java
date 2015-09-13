package de.theit.jenkins.crowd;

import org.acegisecurity.AuthenticationException;

public class CrowdAccessDeniedException extends AuthenticationException {
	public CrowdAccessDeniedException(String msg, Throwable t) {
		super(msg, t);
	}

	public CrowdAccessDeniedException(String msg) {
		super(msg);
	}
}
