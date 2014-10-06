/*
 * @(#)CrowdSecurityRealm.java
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

import com.atlassian.crowd.exception.*;
import com.atlassian.crowd.integration.http.CrowdHttpAuthenticatorImpl;
import com.atlassian.crowd.integration.http.util.CrowdHttpTokenHelperImpl;
import com.atlassian.crowd.integration.http.util.CrowdHttpValidationFactorExtractorImpl;
import com.atlassian.crowd.integration.rest.service.factory.RestCrowdClientFactory;
import com.atlassian.crowd.model.authentication.CookieConfiguration;
import com.atlassian.crowd.model.group.Group;
import com.atlassian.crowd.model.user.User;
import com.atlassian.crowd.service.client.ClientPropertiesImpl;
import groovy.lang.Binding;
import hudson.Extension;
import hudson.Functions;
import hudson.model.Descriptor;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.security.TokenBasedRememberMeServices2;
import hudson.util.FormValidation;
import hudson.util.spring.BeanBuilder;
import jenkins.model.Jenkins;
import org.acegisecurity.*;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.commons.io.input.AutoCloseInputStream;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import static de.theit.jenkins.crowd.ErrorMessages.*;

/**
 * This class provides the security realm for authenticating users against a
 * remote Crowd server.
 * 
 * @author <a href="mailto:theit@gmx.de">Thorsten Heit (theit@gmx.de)</a>
 * @since 06.09.2011
 * @version $Id$
 */
public class CrowdSecurityRealm extends AbstractPasswordBasedSecurityRealm {
	/** Used for logging purposes. */
	private static final Logger LOG = Logger.getLogger(CrowdSecurityRealm.class.getName());

	/** Contains the Crowd server URL. */
	public final String url;

	/** Contains the application name to access Crowd. */
	public final String applicationName;

	/** Contains the application password to access Crowd. */
	public final String password;

	/** Contains the Crowd group to which a user must belong to. */
	public final String group;

	/** Specifies whether nested groups can be used. */
	public final boolean nestedGroups;

	/** Don't use SSO, only REST API authentication. */
	// TODO: Currently this just disables CrowdServletFilter,
	// (auto-logout), maybe worth disabling other SSO handling too.
	public final boolean useSSO;

	/**
	 * The number of minutes to cache authentication validation in the session.
	 * If this value is set to 0, each HTTP request will be authenticated with
	 * the Crowd server.
	 */
    public final int sessionValidationInterval;


    /**
     * A domain to use when setting cookies, overriding the SSO Domain set in Crowd (since Crowd 2.5.2).
     * cookie.domain <a href="https://confluence.atlassian.com/display/CROWD/The+crowd.properties+file">details</a>
     */
    public final String cookieDomain;

    /**
     * SSO cookie name for application.
     * cookie.tokenkey <a href="https://confluence.atlassian.com/display/CROWD/The+crowd.properties+file">details</a>
     */
    public final String cookieTokenkey;

	public final Boolean secure;

    public final Boolean useProxy;
    public final String httpProxyHost;
    public final String httpProxyPort;
    public final String httpProxyUsername;
    public final String httpProxyPassword;

    public final String socketTimeout;
    public final String httpTimeout;
    public final String httpMaxConnections;

    /**
	 * The configuration data necessary for accessing the services on the remote
	 * Crowd server.
	 */
	transient private CrowdConfigurationService configuration;

	/**
	 * Default constructor. Fields in config.jelly must match the parameter
	 * names in the "DataBoundConstructor".
     * @param url
     *            The URL for Crowd.
     * @param applicationName
     *            The application name.
     * @param password
     *            The application password.
     * @param group
     *            The group to which users must belong to. If this parameter is
     *            not specified, a users group membership will not be checked.
     * @param nestedGroups
     *            <code>true</code> when nested groups may be used.
     *            <code>false</code> else.
     * @param sessionValidationInterval
     *            The number of minutes to cache authentication validation in
     *            the session. If this value is set to <code>0</code>, each HTTP
     *            request will be authenticated with the Crowd server.
     * @param useSSO
     *            Enable SSO authentication.
     * @param cookieDomain
     * @param cookieTokenkey
     * @param useProxy
     * @param httpProxyHost
     * @param httpProxyPort
     * @param httpProxyUsername
     * @param httpProxyPassword
     * @param socketTimeout
     * @param httpTimeout
     * @param httpMaxConnections
     */
	@DataBoundConstructor
	public CrowdSecurityRealm(String url, String applicationName, String password, String group, boolean nestedGroups,
                              int sessionValidationInterval, boolean useSSO, String cookieDomain,
                              String cookieTokenkey, Boolean useProxy, String httpProxyHost, String httpProxyPort,
                              String httpProxyUsername, String httpProxyPassword, String socketTimeout,
                              String httpTimeout, String httpMaxConnections, Boolean secure) {
        this.cookieTokenkey = cookieTokenkey;
        this.useProxy = useProxy;
        this.httpProxyHost = httpProxyHost;
        this.httpProxyPort = httpProxyPort;
        this.httpProxyUsername = httpProxyUsername;
        this.httpProxyPassword = httpProxyPassword;
        this.socketTimeout = socketTimeout;
        this.httpTimeout = httpTimeout;
        this.httpMaxConnections = httpMaxConnections;
        this.url = url.trim();
		this.applicationName = applicationName.trim();
		this.password = password.trim();
		this.group = group.trim();
		this.nestedGroups = nestedGroups;
		this.sessionValidationInterval = sessionValidationInterval;
		this.useSSO = useSSO;
        this.cookieDomain = cookieDomain;
		this.secure = secure;
	}

    static public Properties getProperties(String url, String applicationName, String password,
                                           int sessionValidationInterval, boolean useSSO,
                                           String cookieDomain, String cookieTokenkey, Boolean useProxy,
                                           String httpProxyHost, String httpProxyPort, String httpProxyUsername,
                                           String httpProxyPassword, String socketTimeout,
                                           String httpTimeout, String httpMaxConnections){
        // for https://docs.atlassian.com/crowd/2.7.1/com/atlassian/crowd/service/client/ClientPropertiesImpl.html
        Properties props = new Properties();

        String crowdUrl = url;
        if (!crowdUrl.endsWith("/")) {
            crowdUrl += "/";
        }
        props.setProperty("application.name", applicationName);
        props.setProperty("application.password", password);
        props.setProperty("crowd.base.url", crowdUrl);
        props.setProperty("application.login.url", crowdUrl + "console/");
        props.setProperty("crowd.server.url", crowdUrl + "services/");
        props.setProperty("session.validationinterval",	String.valueOf(sessionValidationInterval));
        //TODO move other values to jenkins web configuration
        props.setProperty("session.isauthenticated", "session.isauthenticated");
        props.setProperty("session.tokenkey", "session.tokenkey");
        props.setProperty("session.lastvalidation","session.lastvalidation");

        if (useSSO) {
            if (cookieDomain != null && !cookieDomain.equals(""))
                props.setProperty("cookie.domain", cookieDomain);
            if (cookieTokenkey != null && !cookieTokenkey.equals(""))
                props.setProperty("cookie.tokenkey", cookieTokenkey);
        }

        if (useProxy != null && useProxy){
            if (httpProxyHost != null && !httpProxyHost.equals(""))
                props.setProperty("http.proxy.host", httpProxyHost);
            if (httpProxyPort != null && !httpProxyPort.equals(""))
                props.setProperty("http.proxy.port", httpProxyPort);
            if (httpProxyUsername != null && !httpProxyUsername.equals(""))
                props.setProperty("http.proxy.username", httpProxyUsername);
            if (httpProxyPassword != null && !httpProxyPassword.equals(""))
                props.setProperty("http.proxy.password", httpProxyPassword);
        }

        if (socketTimeout != null && !socketTimeout.equals(""))
            props.setProperty("socket.timeout", socketTimeout);
        if (httpMaxConnections != null && !httpMaxConnections.equals(""))
            props.setProperty("http.max.connections", httpMaxConnections);
        if (httpTimeout != null && !httpTimeout.equals(""))
            props.setProperty("http.timeout", httpTimeout);

        return props;
    }

	/**
	 * {@inheritDoc}
	 * 
	 * @see hudson.security.SecurityRealm#createSecurityComponents()
	 */
	@Override
	public SecurityComponents createSecurityComponents() {
        System.out.println("creating security components");
        Binding binding = new Binding();
        binding.setVariable("instance", this);
		ClassLoader uberClassLoader = Jenkins.getInstance().pluginManager.uberClassLoader;
		BeanBuilder builder = new BeanBuilder(uberClassLoader);
        String fileName = "CrowdSecurityRealmBean.groovy";
        try {
            File override = new File(Jenkins.getInstance().getRootDir(), fileName);
			builder.parse(
                    override.exists() ? new AutoCloseInputStream(new FileInputStream(override)) :
							getClass().getResourceAsStream(fileName), binding);
        } catch (FileNotFoundException e) {
            System.out.println("failed to load "+ fileName);
            throw new Error("Failed to load "+fileName,e);
        }


        WebApplicationContext appContext = builder.createApplicationContext();

        //if (null == configuration) {
        //    configuration = new CrowdConfigurationService(group, nestedGroups);
        configuration = findBean(CrowdConfigurationService.class, appContext);
		configuration.useSSO = useSSO;
		Properties props = getProperties(url, applicationName, password, sessionValidationInterval,
				useSSO, cookieDomain, cookieTokenkey, useProxy, httpProxyHost, httpProxyPort, httpProxyUsername,
				httpProxyPassword, socketTimeout, httpTimeout, httpMaxConnections);
		configuration.clientProperties = ClientPropertiesImpl.newInstanceFromProperties(props);
		configuration.crowdClient = new RestCrowdClientFactory().newInstance(configuration.clientProperties);
		configuration.tokenHelper = CrowdHttpTokenHelperImpl.getInstance(CrowdHttpValidationFactorExtractorImpl.getInstance());
		configuration.crowdHttpAuthenticator = new CrowdHttpAuthenticatorImpl(
				configuration.crowdClient,
				configuration.clientProperties,
				configuration.tokenHelper);
//		configuration.cookieConfiguration = new CookieConfiguration(cookieDomain, false, cookieTokenkey);
		//}

		final UserDetailsService crowdUserDetails = findBean(CrowdUserDetailsService.class, appContext);

        TokenBasedRememberMeServices2 rms = new TokenBasedRememberMeServices2() {
            public Authentication autoLogin(HttpServletRequest request, HttpServletResponse response) {
                try {
                    return super.autoLogin(request, response);
                } catch (Exception e) {// TODO: this check is made redundant with 1.556, but needed with earlier versions
                    cancelCookie(request, response, "Failed to handle remember-me cookie: "+ Functions.printThrowable(e));
                    return null;
                }
            }
        };
        rms.setUserDetailsService(crowdUserDetails);
        rms.setKey(Jenkins.getInstance().getSecretKey());    // use this deprecate method or cookies will missmatch
        rms.setParameter("remember_me"); // this is the form field name in login.jelly

		AuthenticationManager bean = findBean(AuthenticationManager.class, appContext);
		LOG.info("bean: "+bean.toString()+"class: "+bean.getClass().getName());
		return new SecurityComponents(
                bean,
                crowdUserDetails,
                rms
        );
	}

	/**
	 * {@inheritDoc}
	 *
	 * @see hudson.security.SecurityRealm#createFilter(javax.servlet.FilterConfig)
	 */
	@Override
	public Filter createFilter(FilterConfig filterConfig) {
		if (configuration.useSSO) {
			Filter defaultFilter = super.createFilter(filterConfig);
			//adding our filter
			return new CrowdServletFilter(this, configuration, defaultFilter);
		} else {
			return super.createFilter(filterConfig);
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @see hudson.security.AbstractPasswordBasedSecurityRealm#loadUserByUsername(java.lang.String)
	 */
	@Override
	public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException, DataAccessException {
		return getSecurityComponents().userDetails.loadUserByUsername(username);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @see hudson.security.SecurityRealm#loadGroupByGroupname(java.lang.String)
	 */
	@Override
	public GroupDetails loadGroupByGroupname(String groupname)
			throws UsernameNotFoundException, DataAccessException {

		try {
			// load the user object from the remote Crowd server
			if (LOG.isLoggable(Level.FINER)) {
				LOG.finer("Trying to load group: " + groupname);
			}
			final Group crowdGroup = configuration.crowdClient.getGroup(groupname);

			return new GroupDetails() {
				@Override
				public String getName() {
					return crowdGroup.getName();
				}
			};
		} catch (GroupNotFoundException ex) {
			if (LOG.isLoggable(Level.INFO)) {
				LOG.info(groupNotFound(groupname));
			}
			throw new DataRetrievalFailureException(groupNotFound(groupname), ex);
		} catch (ApplicationPermissionException ex) {
			LOG.warning(applicationPermission());
			throw new DataRetrievalFailureException(applicationPermission(), ex);
		} catch (InvalidAuthenticationException ex) {
			LOG.warning(invalidAuthentication());
			throw new DataRetrievalFailureException(invalidAuthentication(), ex);
		} catch (OperationFailedException ex) {
			LOG.log(Level.SEVERE, operationFailed(), ex);
			throw new DataRetrievalFailureException(operationFailed(), ex);
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @see hudson.security.AbstractPasswordBasedSecurityRealm#authenticate(java.lang.String,
	 *      java.lang.String)
	 */
	@Override
	protected UserDetails authenticate(String username, String password) throws AuthenticationException {

		User crowdUser;
		try {
			// authenticate user
			if (LOG.isLoggable(Level.FINE)) {
				LOG.fine("Authenticate user '" + username + "' using password '"
						+ (null != password ? "<available>'": "<not specified>'"));
			}
			crowdUser = this.configuration.crowdClient.authenticateUser(username, password);
		} catch (UserNotFoundException ex) {
			if (LOG.isLoggable(Level.INFO)) {
				LOG.info(userNotFound(username));
			}
			throw new BadCredentialsException(userNotFound(username), ex);
		} catch (ExpiredCredentialException ex) {
			LOG.warning(expiredCredentials(username));
			throw new BadCredentialsException(expiredCredentials(username), ex);
		} catch (InactiveAccountException ex) {
			LOG.warning(accountExpired(username));
			throw new AccountExpiredException(accountExpired(username), ex);
		} catch (ApplicationPermissionException ex) {
			LOG.warning(applicationPermission());
			throw new AuthenticationServiceException(applicationPermission(), ex);
		} catch (InvalidAuthenticationException ex) {
			LOG.warning(invalidAuthentication());
			throw new AuthenticationServiceException(invalidAuthentication(), ex);
		} catch (OperationFailedException ex) {
			LOG.log(Level.SEVERE, operationFailed(), ex);
			throw new AuthenticationServiceException(operationFailed(), ex);
		}

        if (! this.configuration.allowedGroupNames.isEmpty()) {
            // ensure that the group is available, active and that the user
            // is a member of it
            if (!this.configuration.isGroupMember(username)) {
                throw new InsufficientAuthenticationException(userNotValid(username, this.configuration.allowedGroupNames));
            }
        }

		// create the list of granted authorities
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		// add the "authenticated" authority to the list of granted authorities...
		authorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
		// ..and all authorities retrieved from the Crowd server
		authorities.addAll(this.configuration.getAuthoritiesForUser(username));

		return new CrowdUserDetails(crowdUser, authorities);
	}

	/**
	 * Descriptor for {@link CrowdSecurityRealm}. Used as a singleton. The class
	 * is marked as public so that it can be accessed from views.
	 * 
	 * @author <a href="mailto:theit@gmx.de">Thorsten Heit (theit@gmx.de)</a>
	 * @since 06.09.2011 13:35:41
	 * @version $Id$
	 */
	@Extension
	public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
		/**
		 * Default constructor.
		 */
		public DescriptorImpl() {
			super(CrowdSecurityRealm.class);
		}

		/**
		 * Performs on-the-fly validation of the form field 'url'.
		 * 
		 * @param url
		 *            The URL of the Crowd server.
		 * 
		 * @return Indicates the outcome of the validation. This is sent to the
		 *         browser.
		 */
		public FormValidation doCheckUrl(@QueryParameter final String url) {
			if (!Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
				return FormValidation.ok();
			}

			if (0 == url.length()) {
				return FormValidation.error(specifyCrowdUrl());
			}

			return FormValidation.ok();
		}

		/**
		 * Performs on-the-fly validation of the form field 'application name'.
		 * 
		 * @param applicationName
		 *            The application name.
		 * 
		 * @return Indicates the outcome of the validation. This is sent to the
		 *         browser.
		 */
		public FormValidation doCheckApplicationName(
				@QueryParameter final String applicationName) {
			if (!Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
				return FormValidation.ok();
			}

			if (0 == applicationName.length()) {
				return FormValidation.error(specifyApplicationName());
			}

			return FormValidation.ok();
		}

		/**
		 * Performs on-the-fly validation of the form field 'password'.
		 * 
		 * @param password
		 *            The application's password.
		 * 
		 * @return Indicates the outcome of the validation. This is sent to the
		 *         browser.
		 */
		public FormValidation doCheckPassword(
				@QueryParameter final String password) {
			if (!Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
				return FormValidation.ok();
			}

			if (0 == password.length()) {
				return FormValidation.error(specifyApplicationPassword());
			}

			return FormValidation.ok();
		}

		/**
		 * Performs on-the-fly validation of the form field 'session validation
		 * interval'.
		 * 
		 * @param sessionValidationInterval
		 *            The session validation interval time in minutes.
		 * @return Indicates the outcome of the validation. This is sent to the
		 *         browser.
		 */
		public FormValidation doCheckSessionValidationInterval(
				@QueryParameter final String sessionValidationInterval) {
			if (!Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
				return FormValidation.ok();
			}

			try {
				if (0 == sessionValidationInterval.length()
						|| Integer.valueOf(sessionValidationInterval) < 0) {
					return FormValidation.error(specifySessionValidationInterval());
				}
			} catch (NumberFormatException ex) {
				return FormValidation.error(specifySessionValidationInterval());
			}

			return FormValidation.ok();
		}

		/**
		 * Checks whether the connection to the Crowd server can be established
		 * using the given credentials.
		 * 
		 * @param url
		 *            The URL of the Crowd server.
		 * @param applicationName
		 *            The application name.
		 * @param password
		 *            The application's password.
		 * @param group
		 *            The Crowd groups users have to belong to if specified.
		 * 
		 * @return Indicates the outcome of the validation. This is sent to the
		 *         browser.
		 */
		public FormValidation doTestConnection(@QueryParameter String url, @QueryParameter String applicationName,
				@QueryParameter String password, @QueryParameter String group, @QueryParameter boolean useSSO,
                @QueryParameter String cookieDomain, @QueryParameter int sessionValidationInterval,
                @QueryParameter String cookieTokenkey, @QueryParameter Boolean useProxy, @QueryParameter String httpProxyHost,
                @QueryParameter String httpProxyPort, @QueryParameter String httpProxyUsername,
                @QueryParameter String httpProxyPassword, @QueryParameter String socketTimeout,
                @QueryParameter String httpTimeout, @QueryParameter String httpMaxConnections, @QueryParameter Boolean secure)
        {

			CrowdConfigurationService tConfiguration = new CrowdConfigurationService(group, false);
            Properties props = getProperties(url, applicationName, password, sessionValidationInterval,
                    useSSO, cookieDomain, cookieTokenkey, useProxy, httpProxyHost, httpProxyPort, httpProxyUsername,
                    httpProxyPassword, socketTimeout, httpTimeout, httpMaxConnections);
            tConfiguration.clientProperties = ClientPropertiesImpl.newInstanceFromProperties(props);
            tConfiguration.crowdClient = new RestCrowdClientFactory().newInstance(tConfiguration.clientProperties);

			try {
                tConfiguration.crowdClient.testConnection();

				// ensure that the given group names are available and active
				for (String groupName : tConfiguration.allowedGroupNames) {
					if (!tConfiguration.isGroupActive(groupName)) {
						return FormValidation.error(groupNotFound(groupName));
					}
				}

				return FormValidation.ok("OK");
			} catch (InvalidAuthenticationException ex) {
				LOG.log(Level.WARNING, invalidAuthentication(), ex);
				return FormValidation.error(invalidAuthentication());
			} catch (ApplicationPermissionException ex) {
                LOG.log(Level.WARNING, applicationPermission(), ex);
				return FormValidation.error(applicationPermission());
			} catch (OperationFailedException ex) {
                LOG.log(Level.SEVERE, operationFailed(), ex);
				return FormValidation.error(operationFailed());
			} finally {
				tConfiguration.crowdClient.shutdown();
			}
		}

		/**
		 * {@inheritDoc}
		 * 
		 * @see hudson.model.Descriptor#getDisplayName()
		 */
		@Override
		public String getDisplayName() {
			return "Crowd 2";
		}
	}


	public CrowdUserDetails updateUserDetails(CrowdUserDetails d){
         hudson.model.User u = hudson.model.User.get(d.getUsername());
         return d;
     }

    public UserDetails updateUserDetails(UserDetails userDetails){
        if (userDetails instanceof CrowdUserDetails) {
            updateUserDetails((CrowdUserDetails)userDetails);
        }
        return userDetails;
    }

    public Authentication updateUserDetails(Authentication authentication) {
        updateUserDetails((UserDetails) authentication.getPrincipal());
        return authentication;
    }

}
