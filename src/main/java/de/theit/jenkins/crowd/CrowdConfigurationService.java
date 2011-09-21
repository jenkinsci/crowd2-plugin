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

import static de.theit.jenkins.crowd.ErrorMessages.applicationPermission;
import static de.theit.jenkins.crowd.ErrorMessages.groupNotFound;
import static de.theit.jenkins.crowd.ErrorMessages.invalidAuthentication;
import static de.theit.jenkins.crowd.ErrorMessages.operationFailed;
import static de.theit.jenkins.crowd.ErrorMessages.specifyGroup;
import static de.theit.jenkins.crowd.ErrorMessages.userNotFound;

import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;

import com.atlassian.crowd.exception.ApplicationPermissionException;
import com.atlassian.crowd.exception.GroupNotFoundException;
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.exception.UserNotFoundException;
import com.atlassian.crowd.integration.http.CrowdHttpAuthenticator;
import com.atlassian.crowd.integration.http.util.CrowdHttpTokenHelper;
import com.atlassian.crowd.model.group.Group;
import com.atlassian.crowd.service.client.ClientProperties;
import com.atlassian.crowd.service.client.CrowdClient;

/**
 * This class contains all objects that are necessary to access the REST
 * services on the remote Crowd server. In addition to this it contains some
 * helper methods
 * 
 * @author <a href="mailto:theit@gmx.de">Thorsten Heit (theit@gmx.de)</a>
 * @since 08.09.2011
 * @version $Id$
 */
public class CrowdConfigurationService {
	/** Used for logging purposes. */
	private static final Logger LOG = Logger
			.getLogger(CrowdConfigurationService.class.getName());

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

	/**
	 * The group name a user must belong to to be allowed to login into Hudson /
	 * Jenkins.
	 */
	String groupName;

	/** Specifies whether nested groups may be used. */
	private boolean nestedGroups;

	/**
	 * Creates a new Crowd configuration object.
	 * 
	 * @param pGroupName
	 *            The group name to use when authenticating Crowd users. May not
	 *            be <code>null</code>.
	 * @param pNestedGroups
	 *            Specifies whether nested groups should be used when validating
	 *            users against the group name.
	 */
	public CrowdConfigurationService(String pGroupName, boolean pNestedGroups) {
		this.groupName = pGroupName.trim();
		if (0 == this.groupName.length()) {
			throw new IllegalArgumentException(specifyGroup());
		}

		this.nestedGroups = pNestedGroups;
	}

	/**
	 * Checks whether the user is a member of a certain Crowd group whose
	 * members are allowed to login into Hudson / Jenkins.
	 * 
	 * @param username
	 *            The name of the user to check. May not be <code>null</code>.
	 * @return <code>true</code> if and only if the group exists, is active and
	 *         the user is either a direct group member or, if nested groups may
	 *         be used, a nested group member. <code>false</code> else.
	 */
	public boolean isGroupMember(String username) {
		boolean retval = false;

		try {
			if (this.crowdClient.isUserDirectGroupMember(username,
					this.groupName)) {
				retval = true;
			} else if (this.nestedGroups
					&& this.crowdClient.isUserNestedGroupMember(username,
							this.groupName)) {
				retval = true;
			}
		} catch (ApplicationPermissionException ex) {
			LOG.warning(applicationPermission());
		} catch (InvalidAuthenticationException ex) {
			LOG.warning(invalidAuthentication());
		} catch (OperationFailedException ex) {
			LOG.log(Level.SEVERE, operationFailed(), ex);
		}

		return retval;
	}

	/**
	 * Checks if the group exists on the remote Crowd server and is active.
	 * 
	 * @return <code>true</code> if and only if:
	 *         <ul>
	 *         <li>The group name is empty or</li>
	 *         <li>The group name is not empty, does exist on the remote Crowd
	 *         server and is active.</li>
	 *         </ul>
	 *         <code>false</code> else.
	 */
	public boolean isGroupActive() {
		boolean retval = false;
		try {
			Group group = this.crowdClient.getGroup(this.groupName);
			if (null != group) {
				retval = group.isActive();
			}
		} catch (GroupNotFoundException ex) {
			LOG.info(groupNotFound(this.groupName));
		} catch (InvalidAuthenticationException ex) {
			LOG.warning(invalidAuthentication());
		} catch (ApplicationPermissionException ex) {
			LOG.warning(applicationPermission());
		} catch (OperationFailedException ex) {
			LOG.log(Level.SEVERE, operationFailed(), ex);
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
			LOG.fine("Retrieve list of groups with direct membership for user '"
					+ username + "'...");
			while (true) {
				LOG.finest("Fetching groups [" + index + "..."
						+ (index + MAX_GROUPS - 1) + "]...");
				List<Group> groups = this.crowdClient.getGroupsForUser(
						username, index, MAX_GROUPS);
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
			LOG.warning(invalidAuthentication());
		} catch (ApplicationPermissionException ex) {
			LOG.warning(applicationPermission());
		} catch (OperationFailedException ex) {
			LOG.log(Level.SEVERE, operationFailed(), ex);
		}

		// now the same but for nested group membership if this configuration
		// setting is active/enabled
		if (this.nestedGroups) {
			try {
				int index = 0;
				LOG.fine("Retrieve list of groups with direct membership for user '"
						+ username + "'...");
				while (true) {
					LOG.finest("Fetching groups [" + index + "..."
							+ (index + MAX_GROUPS - 1) + "]...");
					List<Group> groups = this.crowdClient
							.getGroupsForNestedUser(username, index, MAX_GROUPS);
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
				LOG.warning(invalidAuthentication());
			} catch (ApplicationPermissionException ex) {
				LOG.warning(applicationPermission());
			} catch (OperationFailedException ex) {
				LOG.log(Level.SEVERE, operationFailed(), ex);
			}
		}

		// now create the list of authorities
		for (String str : groupNames) {
			authorities.add(new GrantedAuthorityImpl(str));
		}

		return authorities;
	}
}
