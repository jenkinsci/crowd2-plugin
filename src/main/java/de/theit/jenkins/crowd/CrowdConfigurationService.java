/*
 * @(#)CrowdConfigurationService.java
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
import com.atlassian.crowd.integration.http.CrowdHttpAuthenticator;
import com.atlassian.crowd.integration.http.util.CrowdHttpTokenHelper;
import com.atlassian.crowd.model.authentication.CookieConfiguration;
import com.atlassian.crowd.model.group.Group;
import com.atlassian.crowd.service.client.ClientProperties;
import com.atlassian.crowd.service.client.CrowdClient;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

import java.util.*;

import static de.theit.jenkins.crowd.ErrorMessages.*;

/**
 * This class contains all objects that are necessary to access the REST
 * services on the remote Crowd server. Additionally it contains some helper
 * methods to check for group membership and availability.
 * 
 * @author <a href="mailto:theit@gmx.de">Thorsten Heit (theit@gmx.de)</a>
 * @since 08.09.2011
 * @version $Id$
 */
public class CrowdConfigurationService implements InitializingBean {
	/** Used for logging purposes. */
	private static final Logger LOG = LoggerFactory.getLogger(CrowdConfigurationService.class);

	/**
	 * The maximum number of groups that can be fetched from the Crowd server
	 * for a user in one request.
	 */
	private static final int MAX_GROUPS = 500;

	/** Holds the Crowd client properties. */
	ClientProperties clientProperties;

	/** The Crowd client to access the REST services on the remote Crowd server. */
	CrowdClient crowdClient;

	/** The helper class for Crowd SSO token operations. */
	CrowdHttpTokenHelper tokenHelper;

	/**
	 * The interface used to manage HTTP authentication and web/SSO
	 * authentication integration.
	 */
	CrowdHttpAuthenticator crowdHttpAuthenticator;

	/** The names of all user groups that are allowed to login. */
	List<String> allowedGroupNames;

	/** Specifies whether nested groups may be used. */
	private boolean nestedGroups;

    public boolean useSSO;

	public CookieConfiguration cookieConfiguration;

    /**
     * Creates a new Crowd configuration object.
     *
     * @param pGroupNames
     *            The group names to use when authenticating Crowd users. May
     *            not be <code>null</code>.
     * @param pNestedGroups
     *            Specifies whether nested groups should be used when validating
     *            users against a group name.
     */
	public CrowdConfigurationService(String pGroupNames, boolean pNestedGroups) {
			LOG.info("Groups given for Crowd configuration service: {}", pGroupNames);
		this.allowedGroupNames = new ArrayList<String>();
		for (String group : pGroupNames.split(",")) {
			if (null != group && group.trim().length() > 0) {
				LOG.debug("-> adding allowed group name: {}", group);
				this.allowedGroupNames.add(group);
			}
		}

		this.nestedGroups = pNestedGroups;
	}

	/**
	 * Checks whether the user is a member of one of the Crowd groups whose
	 * members are allowed to login.
	 * 
	 * @param username
	 *            The name of the user to check. May not be <code>null</code> or
	 *            empty.
	 * @return <code>true</code> if and only if the group exists, is active and
	 *         the user is either a direct group member or, if nested groups may
	 *         be used, a nested group member. <code>false</code> else.
	 */
	public boolean isGroupMember(String username) {
		boolean retval = false;

		try {
			for (String group : this.allowedGroupNames) {
				retval = isGroupMember(username, group);
				if (retval) {
					break;
				}
			}
		} catch (ApplicationPermissionException ex) {
			LOG.warn(applicationPermission());
		} catch (InvalidAuthenticationException ex) {
			LOG.warn(invalidAuthentication());
		} catch (OperationFailedException ex) {
			LOG.error(operationFailed(), ex);
		}

		return retval;
	}

	/**
	 * Checks whether the user is a member of the given Crowd group.
	 * 
	 * @param username
	 *            The name of the user to check. May not be <code>null</code> or
	 *            empty.
	 * @param group
	 *            The name of the group to check the user against. May not be
	 *            <code>null</code>.
	 * @return <code>true</code> if and only if the group exists, is active and
	 *         the user is either a direct group member or, if nested groups may
	 *         be used, a nested group member. <code>false</code> else.
	 * 
	 * @throws ApplicationPermissionException
	 *             If the application is not permitted to perform the requested
	 *             operation on the server.
	 * @throws InvalidAuthenticationException
	 *             If the application and password are not valid.
	 * @throws OperationFailedException
	 *             If the operation has failed for any other reason, including
	 *             invalid arguments and the operation not being supported on
	 *             the server.
	 */
	private boolean isGroupMember(String username, String group)
			throws ApplicationPermissionException, InvalidAuthenticationException, OperationFailedException {
		boolean retval = false;

		if (isGroupActive(group)) {
			LOG.info("Checking group membership for user '{}' and group '{}'...", username, group);
			if (this.crowdClient.isUserDirectGroupMember(username, group)) {
				retval = true;
				LOG.debug("=> user is a direct group member");
			} else if (this.nestedGroups && this.crowdClient.isUserNestedGroupMember(username, group)) {
				retval = true;
				LOG.debug("=> user is a nested group member");
			}
		}

		return retval;
	}

	/**
	 * Checks if the specified group name exists on the remote Crowd server and
	 * is active.
	 * 
	 * @param groupName
	 *            The name of the group to check. May not be <code>null</code>
	 *            or empty.
	 * @return <code>true</code> if and only if the group name is not empty,
	 *         does exist on the remote Crowd server and is active.
	 *         <code>false</code> else.
	 * @throws InvalidAuthenticationException
	 *             If the application and password are not valid.
	 * @throws ApplicationPermissionException
	 *             If the application is not permitted to perform the requested
	 *             operation on the server
	 * @throws OperationFailedException
	 *             If the operation has failed for any other reason, including
	 *             invalid arguments and the operation not being supported on
	 *             the server.
	 */
	public boolean isGroupActive(String groupName)
			throws InvalidAuthenticationException, ApplicationPermissionException, OperationFailedException {
		boolean retval = false;

		try {
			LOG.debug("Checking whether group is active: " + groupName);
			Group group = this.crowdClient.getGroup(groupName);
			if (null != group) {
				retval = group.isActive();
			}
		} catch (GroupNotFoundException ex) {
			LOG.debug(groupNotFound(groupName));
		}

		return retval;
	}

	/**
	 * Retrieves the list of all (nested) groups from the Crowd server that the
	 * user is a member of.
	 * 
	 * @param username
	 *            The name of the user. May not be <code>null</code>.
	 * @return The list of all groups that the user is a member of. Always
	 *         non-null.
	 */
	public Collection<GrantedAuthority> getAuthoritiesForUser(String username) {
		Collection<GrantedAuthority> authorities = new TreeSet<GrantedAuthority>(
				new Comparator<GrantedAuthority>() {
					@Override
					public int compare(GrantedAuthority ga1,
							GrantedAuthority ga2) {
						return ga1.getAuthority().compareTo(ga2.getAuthority());
					}
				});

		HashSet<String> groupNames = new HashSet<String>();

		// retrieve the names of all groups the user is a direct member of
		try {
			int index = 0;
			LOG.debug("Retrieve list of groups with direct membership for user '{}'...", username);
			while (true) {
				LOG.debug("Fetching groups [" + index + "..." + (index + MAX_GROUPS - 1) + "]...");
				List<Group> groups = this.crowdClient.getGroupsForUser(username, index, MAX_GROUPS);
				if (null == groups || groups.isEmpty()) {
					break;
				}
				for (Group group : groups) {
					if (group.isActive()) {
						groupNames.add(group.getName());
					}
				}
				index += MAX_GROUPS;
			}
		} catch (UserNotFoundException ex) {
			LOG.info(userNotFound(username));
		} catch (InvalidAuthenticationException ex) {
			LOG.warn(invalidAuthentication());
		} catch (ApplicationPermissionException ex) {
			LOG.warn(applicationPermission());
		} catch (OperationFailedException ex) {
			LOG.error(operationFailed(), ex);
		}

		// now the same but for nested group membership if this configuration
		// setting is active/enabled
		if (this.nestedGroups) {
			try {
				int index = 0;
				LOG.debug("Retrieve list of groups with direct membership for user '" + username + "'...");
				while (true) {
					LOG.debug("Fetching groups [" + index + "..." + (index + MAX_GROUPS - 1) + "]...");
					List<Group> groups = this.crowdClient.getGroupsForNestedUser(username, index, MAX_GROUPS);
					if (null == groups || groups.isEmpty()) {
						break;
					}
					for (Group group : groups) {
						if (group.isActive()) {
							groupNames.add(group.getName());
						}
					}
					index += MAX_GROUPS;
				}
			} catch (UserNotFoundException ex) {
				LOG.info(userNotFound(username));
			} catch (InvalidAuthenticationException ex) {
				LOG.warn(invalidAuthentication());
			} catch (ApplicationPermissionException ex) {
				LOG.warn(applicationPermission());
			} catch (OperationFailedException ex) {
				LOG.error(operationFailed(), ex);
			}
		}

		// now create the list of authorities
		for (String str : groupNames) {
			LOG.info("adding authority: "+str);
            authorities.add(new GrantedAuthorityImpl(str));
		}

		return authorities;
	}

    @Override
    public void afterPropertiesSet() throws Exception {
        LOG.info("afterPropertiesSet()");
    }
}
