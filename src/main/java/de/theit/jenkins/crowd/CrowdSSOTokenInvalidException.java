package de.theit.jenkins.crowd;

import org.acegisecurity.BadCredentialsException;

public class CrowdSSOTokenInvalidException extends BadCredentialsException
{
	public CrowdSSOTokenInvalidException(String msg, Throwable t)
	{
		super(msg, t);
	}

	public CrowdSSOTokenInvalidException(String msg)
	{
		super(msg);
	}
}