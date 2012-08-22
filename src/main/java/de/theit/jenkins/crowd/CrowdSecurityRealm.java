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

import static de.theit.jenkins.crowd.ErrorMessages.accountExpired;
import static de.theit.jenkins.crowd.ErrorMessages.applicationPermission;
import static de.theit.jenkins.crowd.ErrorMessages.cannotLoadCrowdProperties;
import static de.theit.jenkins.crowd.ErrorMessages.expiredCredentials;
import static de.theit.jenkins.crowd.ErrorMessages.groupNotFound;
import static de.theit.jenkins.crowd.ErrorMessages.invalidAuthentication;
import static de.theit.jenkins.crowd.ErrorMessages.operationFailed;
import static de.theit.jenkins.crowd.ErrorMessages.specifyApplicationName;
import static de.theit.jenkins.crowd.ErrorMessages.specifyApplicationPassword;
import static de.theit.jenkins.crowd.ErrorMessages.specifyCrowdUrl;
import static de.theit.jenkins.crowd.ErrorMessages.specifyGroup;
import static de.theit.jenkins.crowd.ErrorMessages.specifySessionValidationInterval;
import static de.theit.jenkins.crowd.ErrorMessages.userNotFound;
import static de.theit.jenkins.crowd.ErrorMessages.userNotValid;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.Hudson;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;

import org.acegisecurity.AccountExpiredException;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.InsufficientAuthenticationException;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataRetrievalFailureException;

import com.atlassian.crowd.exception.ApplicationPermissionException;
import com.atlassian.crowd.exception.ExpiredCredentialException;
import com.atlassian.crowd.exception.GroupNotFoundException;
import com.atlassian.crowd.exception.InactiveAccountException;
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.exception.UserNotFoundException;
import com.atlassian.crowd.integration.http.CrowdHttpAuthenticatorImpl;
import com.atlassian.crowd.integration.http.util.CrowdHttpTokenHelperImpl;
import com.atlassian.crowd.integration.http.util.CrowdHttpValidationFactorExtractorImpl;
import com.atlassian.crowd.integration.rest.service.factory.RestCrowdClientFactory;
import com.atlassian.crowd.model.group.Group;
import com.atlassian.crowd.model.user.User;
import com.atlassian.crowd.service.client.ClientPropertiesImpl;

/**
 * This class provides the Jenkins security realm for authenticating users
 * against a remote Crowd server.
 * 
 * @author <a href="mailto:theit@gmx.de">Thorsten Heit (theit@gmx.de)</a>
 * @since 06.09.2011
 * @version $Id$
 */
public class CrowdSecurityRealm extends AbstractPasswordBasedSecurityRealm {
	/** Used for logging purposes. */
	private static final Logger LOG = Logger.getLogger(CrowdSecurityRealm.class
			.getName());

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

	/**
	 * The number of minutes to cache authentication validation in the session.
	 * If this value is set to 0, each HTTP request will be authenticated with
	 * the Crowd server.
	 */
	private final int sessionValidationInterval;

	/**
	 * The configuration data necessary for accessing the services on the remote
	 * Crowd server.
	 */
	transient private CrowdConfigurationService configuration;

	/**
	 * Default constructor. Fields in config.jelly must match the parameter
	 * names in the "DataBoundConstructor".
	 * 
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
	 */
	@SuppressWarnings("hiding")
	@DataBoundConstructor
	public CrowdSecurityRealm(String url, String applicationName,
			String password, String group, boolean nestedGroups,
			int sessionValidationInterval) {
		this.url = url.trim();
		this.applicationName = applicationName.trim();
		this.password = password.trim();
		this.group = group.trim();
		this.nestedGroups = nestedGroups;
		this.sessionValidationInterval = sessionValidationInterval;
	}

	/**
	 * Initializes all objects necessary to talk to / with Crowd.
	 */
	private void initializeConfiguration() {
		// configure the ClientProperties object
		Properties props = new Properties();
		try {
			props.load(getClass().getResourceAsStream("/crowd.properties"));
		} catch (IOException ex) {
			LOG.log(Level.SEVERE, cannotLoadCrowdProperties(), ex);
		}

		if (this.applicationName != null || this.password != null
				|| this.url != null) {
			String crowdUrl = this.url;
			if (!crowdUrl.endsWith("/")) {
				crowdUrl += "/";
			}
			props.setProperty("application.name", this.applicationName);
			props.setProperty("application.password", this.password);
			props.setProperty("crowd.base.url", crowdUrl);
			props.setProperty("application.login.url", crowdUrl + "console/");
			props.setProperty("crowd.server.url", this.url + "services/");
			props.setProperty("session.validationinterval",
					String.valueOf(this.sessionValidationInterval));
		} else {
			LOG.warning("Client properties are incomplete");
		}

		this.configuration = new CrowdConfigurationService(this.group,
				this.nestedGroups);

		this.configuration.clientProperties = ClientPropertiesImpl
				.newInstanceFromProperties(props);
		this.configuration.crowdClient = new RestCrowdClientFactory()
				.newInstance(this.configuration.clientProperties);

		this.configuration.tokenHelper = CrowdHttpTokenHelperImpl
				.getInstance(CrowdHttpValidationFactorExtractorImpl
						.getInstance());
		this.configuration.crowdHttpAuthenticator = new CrowdHttpAuthenticatorImpl(
				this.configuration.crowdClient,
				this.configuration.clientProperties,
				this.configuration.tokenHelper);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @see hudson.security.SecurityRealm#createSecurityComponents()
	 */
	@Override
	public SecurityComponents createSecurityComponents() {
		if (null == this.configuration) {
			initializeConfiguration();
		}

		CrowdRememberMeServices ssoService = new CrowdRememberMeServices(
				this.configuration);

		AuthenticationManager crowdAuthenticationManager = new CrowdAuthenticationManager(
				this.configuration);
		UserDetailsService crowdUserDetails = new CrowdUserDetailsService(
				this.configuration);

		return new SecurityComponents(crowdAuthenticationManager,
				crowdUserDetails, ssoService);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @see hudson.security.SecurityRealm#doLogout(org.kohsuke.stapler.StaplerRequest,
	 *      org.kohsuke.stapler.StaplerResponse)
	 */
	@Override
	public void doLogout(StaplerRequest req, StaplerResponse rsp)
			throws IOException, ServletException {
		SecurityRealm realm = Hudson.getInstance().getSecurityRealm();

		if (realm instanceof CrowdSecurityRealm
				&& realm.getSecurityComponents().rememberMe instanceof CrowdRememberMeServices) {
			((CrowdRememberMeServices) realm.getSecurityComponents().rememberMe)
					.logout(req, rsp);
		}

		super.doLogout(req, rsp);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @see hudson.security.SecurityRealm#createFilter(javax.servlet.FilterConfig)
	 */
	@Override
	public Filter createFilter(FilterConfig filterConfig) {
		if (null == this.configuration) {
			initializeConfiguration();
		}

		Filter defaultFilter = super.createFilter(filterConfig);

		return new CrowdServletFilter(this, this.configuration, defaultFilter);
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
			final Group crowdGroup = this.configuration.crowdClient
					.getGroup(groupname);

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
			throw new DataRetrievalFailureException(groupNotFound(groupname),
					ex);
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
	protected UserDetails authenticate(String pUsername, String pPassword)
			throws AuthenticationException {
		// ensure that the group is available, active and that the user
		// is a member of it
		if (!this.configuration.isGroupMember(pUsername)) {
			throw new InsufficientAuthenticationException(userNotValid(
					pUsername, this.configuration.allowedGroupNames));
		}

		User user;
		try {
			// authenticate user
			if (LOG.isLoggable(Level.FINE)) {
				LOG.fine("Authenticate user '"
						+ pUsername
						+ "' using password '"
						+ (null != pPassword ? "<available>'"
								: "<not specified>'"));
			}
			user = this.configuration.crowdClient.authenticateUser(pUsername,
					pPassword);
		} catch (UserNotFoundException ex) {
			if (LOG.isLoggable(Level.INFO)) {
				LOG.info(userNotFound(pUsername));
			}
			throw new BadCredentialsException(userNotFound(pUsername), ex);
		} catch (ExpiredCredentialException ex) {
			LOG.warning(expiredCredentials(pUsername));
			throw new BadCredentialsException(expiredCredentials(pUsername), ex);
		} catch (InactiveAccountException ex) {
			LOG.warning(accountExpired(pUsername));
			throw new AccountExpiredException(accountExpired(pUsername), ex);
		} catch (ApplicationPermissionException ex) {
			LOG.warning(applicationPermission());
			throw new AuthenticationServiceException(applicationPermission(),
					ex);
		} catch (InvalidAuthenticationException ex) {
			LOG.warning(invalidAuthentication());
			throw new AuthenticationServiceException(invalidAuthentication(),
					ex);
		} catch (OperationFailedException ex) {
			LOG.log(Level.SEVERE, operationFailed(), ex);
			throw new AuthenticationServiceException(operationFailed(), ex);
		}

		// create the list of granted authorities
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		// add the "authenticated" authority to the list of granted
		// authorities...
		authorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
		// ..and all authorities retrieved from the Crowd server
		authorities.addAll(this.configuration.getAuthoritiesForUser(pUsername));

		return new CrowdUser(user, authorities);
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
			if (!Hudson.getInstance().hasPermission(Hudson.ADMINISTER)) {
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
			if (!Hudson.getInstance().hasPermission(Hudson.ADMINISTER)) {
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
			if (!Hudson.getInstance().hasPermission(Hudson.ADMINISTER)) {
				return FormValidation.ok();
			}

			if (0 == password.length()) {
				return FormValidation.error(specifyApplicationPassword());
			}

			return FormValidation.ok();
		}

		/**
		 * Performs on-the-fly validation of the form field 'group name'.
		 * 
		 * @param group
		 *            The group name.
		 * 
		 * @return Indicates the outcome of the validation. This is sent to the
		 *         browser.
		 */
		public FormValidation doCheckGroup(@QueryParameter final String group) {
			if (!Hudson.getInstance().hasPermission(Hudson.ADMINISTER)) {
				return FormValidation.ok();
			}

			if (0 == group.length()) {
				return FormValidation.error(specifyGroup());
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
			if (!Hudson.getInstance().hasPermission(Hudson.ADMINISTER)) {
				return FormValidation.ok();
			}

			try {
				if (0 == sessionValidationInterval.length()
						|| Integer.valueOf(sessionValidationInterval)
								.intValue() < 0) {
					return FormValidation
							.error(specifySessionValidationInterval());
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
		public FormValidation doTestConnection(@QueryParameter String url,
				@QueryParameter String applicationName,
				@QueryParameter String password, @QueryParameter String group) {
			Logger log = Logger.getLogger(getClass().getName());

			Properties props = new Properties();
			props.setProperty("application.name", applicationName);
			props.setProperty("application.password", password);
			props.setProperty("crowd.server.url", url);
			props.setProperty("session.validationinterval", "5");

			CrowdConfigurationService configuration = new CrowdConfigurationService(
					group, false);
			configuration.clientProperties = ClientPropertiesImpl
					.newInstanceFromProperties(props);
			configuration.crowdClient = new RestCrowdClientFactory()
					.newInstance(configuration.clientProperties);

			try {
				configuration.crowdClient.testConnection();

				// ensure that the given group names are available and active
				for (String groupName : configuration.allowedGroupNames) {
					if (!configuration.isGroupActive(groupName)) {
						return FormValidation.error(groupNotFound(groupName));
					}
				}

				return FormValidation.ok();
			} catch (InvalidAuthenticationException ex) {
				log.log(Level.WARNING, invalidAuthentication(), ex);
				return FormValidation.error(invalidAuthentication());
			} catch (ApplicationPermissionException ex) {
				log.log(Level.WARNING, applicationPermission(), ex);
				return FormValidation.error(applicationPermission());
			} catch (OperationFailedException ex) {
				log.log(Level.SEVERE, operationFailed(), ex);
				return FormValidation.error(operationFailed());
			} finally {
				configuration.crowdClient.shutdown();
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
}
