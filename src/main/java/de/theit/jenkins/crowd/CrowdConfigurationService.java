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

import com.atlassian.crowd.exception.ApplicationAccessDeniedException;
import com.atlassian.crowd.exception.ApplicationPermissionException;
import com.atlassian.crowd.exception.ExpiredCredentialException;
import com.atlassian.crowd.exception.GroupNotFoundException;
import com.atlassian.crowd.exception.InactiveAccountException;
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.InvalidTokenException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.exception.UserNotFoundException;
import com.atlassian.crowd.integration.http.CrowdHttpAuthenticator;
import com.atlassian.crowd.integration.http.CrowdHttpAuthenticatorImpl;
import com.atlassian.crowd.integration.http.util.CrowdHttpTokenHelper;
import com.atlassian.crowd.integration.http.util.CrowdHttpTokenHelperImpl;
import com.atlassian.crowd.integration.http.util.CrowdHttpValidationFactorExtractorImpl;
import com.atlassian.crowd.integration.rest.service.factory.RestCrowdClientFactory;
import com.atlassian.crowd.model.authentication.ValidationFactor;
import com.atlassian.crowd.model.group.Group;
import com.atlassian.crowd.model.user.User;
import com.atlassian.crowd.service.client.ClientProperties;
import com.atlassian.crowd.service.client.ClientPropertiesImpl;
import com.atlassian.crowd.service.client.CrowdClient;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import hudson.util.Secret;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.SystemUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static de.theit.jenkins.crowd.ErrorMessages.applicationPermission;
import static de.theit.jenkins.crowd.ErrorMessages.groupNotFound;
import static de.theit.jenkins.crowd.ErrorMessages.invalidAuthentication;
import static de.theit.jenkins.crowd.ErrorMessages.operationFailed;
import static de.theit.jenkins.crowd.ErrorMessages.userNotFound;

/**
 * This class contains all objects that are necessary to access the REST
 * services on the remote Crowd server. Additionally it contains some helper
 * methods to check for group membership and availability.
 *
 * @author <a href="mailto:theit@gmx.de">Thorsten Heit (theit@gmx.de)</a>
 * @version $Id$
 * @since 08.09.2011
 */
public class CrowdConfigurationService {

    /**
     * Classloader problem with Java 11 and jaxb
     *
     */
    // TODO remove it if a better solutions is found without classloader hack
    // @Issue("JENKINS-59301")
    private static final boolean IS_MIN_JAVA_11 = SystemUtils.JAVA_VERSION_FLOAT >= 11.0f;

    /**
     * Used for logging purposes.
     */
    private static final Logger LOG = Logger.getLogger(CrowdConfigurationService.class.getName());

    /**
     * The maximum number of groups that can be fetched from the Crowd server
     * for a user in one request.
     */
    private static final int MAX_GROUPS = 500;

    /**
     * Holds the Crowd client properties.
     */
    private final ClientProperties clientProperties;

    /**
     * The Crowd client to access the REST services on the remote Crowd server.
     */
    private final CrowdClient crowdClient;

    /**
     * The helper class for Crowd SSO token operations.
     */
    private final CrowdHttpTokenHelper tokenHelper;

    /**
     * The interface used to manage HTTP authentication and web/SSO
     * authentication integration.
     */
    private final CrowdHttpAuthenticator crowdHttpAuthenticator;

    /**
     * The names of all user groups that are allowed to login.
     */
    private final ArrayList<String> allowedGroupNames;

    /**
     * Specifies whether nested groups may be used.
     */
    private final boolean nestedGroups;

    private final boolean useSSO;

    private final boolean useCache;

    private final Integer cacheSize;

    private final Integer cacheTTL;

    private Cache<String, Boolean> isGroupMemberCache = null;

    private Cache<String, User> userFromSSOTokenCache = null;

    private Cache<String, User> userCache = null;

    private Cache<String, Group> groupCache = null;

    private Cache<String, Collection<GrantedAuthority>> authoritiesForUserCache = null;

    /**
     * Creates a new Crowd configuration object.
     *
     * @param url                       The Crowd URL
     * @param applicationName           The Crowd application name
     * @param password                  The Crowd application password
     * @param sessionValidationInterval The session validation interval
     * @param useSSO                    Specifies if SSO should be enabled
     * @param cookieDomain              The cookie domain
     * @param cookieTokenkey            The cookie token key
     * @param useProxy                  the Specifies if a proxy should be used
     * @param httpProxyHost             The http proxy host
     * @param httpProxyPort             The http proxy port
     * @param httpProxyUsername         The http proxy username
     * @param httpProxyPassword         The http proxy password
     * @param socketTimeout             The socket timeout
     * @param httpTimeout               The http timeout
     * @param httpMaxConnections        The http max connections
     * @param useCache                  The use cache
     * @param cacheSize                 the cache size
     * @param cacheTTL                  The cache TTL
     * @param pGroupNames               The group names to use when authenticating
     *                                  Crowd users. May
     *                                  not be <code>null</code>.
     * @param pNestedGroups             Specifies whether nested groups should be
     *                                  used when validating
     *                                  users against a group name.
     */
    public CrowdConfigurationService(String url, String applicationName, Secret password,
            int sessionValidationInterval, boolean useSSO,
            String cookieDomain, String cookieTokenkey, Boolean useProxy,
            String httpProxyHost, String httpProxyPort, String httpProxyUsername,
            Secret httpProxyPassword, String socketTimeout,
            String httpTimeout, String httpMaxConnections,
            boolean useCache, Integer cacheSize, Integer cacheTTL,
            String pGroupNames, boolean pNestedGroups) {

        LOG.log(Level.INFO, "Groups given for Crowd configuration service: {0}", pGroupNames);

        this.allowedGroupNames = new ArrayList<>();
        for (String group : pGroupNames.split(",")) {
            group = group.trim();
            if (group.length() > 0) {
                LOG.log(Level.FINE, "-> adding allowed group name: {0}", group);
                this.allowedGroupNames.add(group);
            }
        }
        this.nestedGroups = pNestedGroups;
        this.useSSO = useSSO;
        this.useCache = useCache;
        this.cacheSize = cacheSize;
        this.cacheTTL = cacheTTL;

        if (cacheSize != null && cacheSize > 0) {
            this.isGroupMemberCache = CacheBuilder.newBuilder().maximumSize(cacheSize).expireAfterWrite(cacheTTL, TimeUnit.MINUTES).build();
            this.userFromSSOTokenCache = CacheBuilder.newBuilder().maximumSize(cacheSize).expireAfterWrite(cacheTTL, TimeUnit.MINUTES).build();
            this.userCache = CacheBuilder.newBuilder().maximumSize(cacheSize).expireAfterWrite(cacheTTL, TimeUnit.MINUTES).build();
            this.groupCache = CacheBuilder.newBuilder().maximumSize(cacheSize).expireAfterWrite(cacheTTL, TimeUnit.MINUTES).build();
            this.authoritiesForUserCache = CacheBuilder.newBuilder().maximumSize(cacheSize).expireAfterWrite(cacheTTL, TimeUnit.MINUTES).build();
        }

        Properties props = getProperties(url, applicationName, password, sessionValidationInterval,
                useSSO, cookieDomain, cookieTokenkey, useProxy, httpProxyHost, httpProxyPort, httpProxyUsername,
                httpProxyPassword, socketTimeout, httpTimeout, httpMaxConnections);
        this.clientProperties = ClientPropertiesImpl.newInstanceFromProperties(props);
        this.crowdClient = new RestCrowdClientFactory().newInstance(this.clientProperties);
        this.tokenHelper = CrowdHttpTokenHelperImpl.getInstance(CrowdHttpValidationFactorExtractorImpl.getInstance());
        this.crowdHttpAuthenticator = new CrowdHttpAuthenticatorImpl(
                this.crowdClient,
                this.clientProperties,
                this.tokenHelper);
    }

    public List<String> getAllowedGroupNames() {
        return allowedGroupNames;
    }

    public boolean isUseSSO() {
        return useSSO;
    }

    /**
     * Checks whether the user is a member of one of the Crowd groups whose
     * members are allowed to login.
     *
     * @param username The name of the user to check. May not be <code>null</code>
     *                 or empty.
     * @return <code>true</code> if and only if the group exists, is active and
     *         the user is either a direct group member or, if nested groups may
     *         be used, a nested group member. <code>false</code> else.
     */
    public boolean isGroupMember(String username) {
        if (username == null) {
            return false;
        }

        if (allowedGroupNames.isEmpty()) {
            return true;
        }

        // Load the entry from cache if it's valid return it
        Boolean retval = getValidValueFromCache(username, isGroupMemberCache);
        if (retval != null) {
            LOG.log(Level.FINEST, "isGroupMember() cache hit: {0}", username);
            return Boolean.TRUE.equals(retval);
        }

        LOG.log(Level.FINEST, "isGroupMember() cache hit MISS: {0}", username);

        // no entry was found try to get one
        try {
            for (String group : this.allowedGroupNames) {
                retval = isGroupMember(username, group);
                if (retval) {
                    // If correct object was returned save it to cache
                    // checking if key is present is redundant
                    setValueToCache(username, retval, isGroupMemberCache);
                    break;
                }
            }
        } catch (ApplicationPermissionException ex) {
            LOG.log(Level.WARNING, applicationPermission());
            retval = null;
        } catch (InvalidAuthenticationException ex) {
            LOG.log(Level.WARNING, invalidAuthentication());
            retval = null;
        } catch (OperationFailedException ex) {
            LOG.log(Level.SEVERE, operationFailed(), ex);
            retval = null;
        }

        return Boolean.TRUE.equals(retval);
    }

    /**
     * Checks if the specified group name exists on the remote Crowd server and
     * is active.
     *
     * @param groupName The name of the group to check. May not be <code>null</code>
     *                  or empty.
     * @return <code>true</code> if and only if the group name is not empty,
     *         does exist on the remote Crowd server and is active.
     *         <code>false</code> else.
     * @throws InvalidAuthenticationException If the application and password are
     *                                        not valid.
     * @throws ApplicationPermissionException If the application is not permitted to
     *                                        perform the requested operation on the
     *                                        server
     * @throws OperationFailedException       If the operation has failed for any
     *                                        other reason, including
     *                                        invalid arguments and the operation
     *                                        not being supported on
     *                                        the server.
     */
    public boolean isGroupActive(String groupName)
            throws InvalidAuthenticationException,
            ApplicationPermissionException, OperationFailedException {
        boolean retval = false;

        try {
            LOG.log(Level.FINE, "Checking whether group is active: {0}", groupName);
            Group group = getGroup(groupName);
            if (null != group) {
                retval = group.isActive();
            }
        } catch (GroupNotFoundException ex) {
            LOG.log(Level.FINE, groupNotFound(groupName));
        }

        return retval;
    }

    /**
     * Retrieves the list of all (nested) groups from the Crowd server that the
     * user is a member of.
     *
     * @param username The name of the user. May not be <code>null</code>.
     * @return The list of all groups that the user is a member of. Always
     *         non-null.
     */
    public Collection<GrantedAuthority> getAuthoritiesForUser(String username) {
        if (username == null) {
            return null; // prevent NPE
        }

        // Load the entry from cache if it's valid return it
        Collection<GrantedAuthority> authorities = getValidValueFromCache(username, authoritiesForUserCache);
        if (authorities != null) {
            LOG.log(Level.FINEST, "getAuthoritiesForUser() cache hit: {0}", username);
            return authorities;
        }

        LOG.log(Level.FINEST, "getAuthoritiesForUser() cache MISS: {0}", username);

        // no cache entry was found try to get one
        authorities = new TreeSet<>(
                new Comparator<GrantedAuthority>() {
                    @Override
                    public int compare(GrantedAuthority ga1,
                            GrantedAuthority ga2) {
                        return ga1.getAuthority().compareTo(ga2.getAuthority());
                    }
                });
        HashSet<String> groupNames = new HashSet<>();

        // retrieve the names of all groups the user is a directly or indirectly member
        // of if this configuration setting is active/enabled
        try {
            int index = 0;
            String membership = this.nestedGroups ? "nested" : "direct";
            LOG.log(Level.FINE, "Retrieve list of groups with {0} membership for user ''{1}''...",
                    new Object[] { membership, username });

            while (true) {
                LOG.log(Level.FINEST, "Fetching groups [{0}...{1}]...",
                        new Object[] { index, (index + MAX_GROUPS - 1) });

                List<Group> groups;
                if (this.nestedGroups) {
                    groups = getGroupsForNestedUser(username, index, MAX_GROUPS);
                } else {
                    groups = getGroupsForUser(username, index, MAX_GROUPS);
                }

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
            LOG.log(Level.INFO, userNotFound(username));
        } catch (InvalidAuthenticationException ex) {
            LOG.log(Level.WARNING, invalidAuthentication());
        } catch (ApplicationPermissionException ex) {
            LOG.log(Level.WARNING, applicationPermission());
        } catch (OperationFailedException ex) {
            LOG.log(Level.SEVERE, operationFailed(), ex);
        }

        // now create the list of authorities
        for (String str : groupNames) {
            authorities.add(new SimpleGrantedAuthority(str));
        }

        // If correct object was returned save it to cache
        // checking if key is present is redundant
        setValueToCache(username, authorities, authoritiesForUserCache);

        return authorities;
    }

    public User authenticateUser(String login, String password) throws UserNotFoundException, InactiveAccountException,
            ExpiredCredentialException, ApplicationPermissionException, InvalidAuthenticationException,
            OperationFailedException {
        LOG.log(Level.FINEST, "CrowdClient.authenticateUser()");
        ClassLoader orgContextClassLoader = null;
        Thread currentThread = null;
        if (IS_MIN_JAVA_11) {
            currentThread = Thread.currentThread();
            orgContextClassLoader = currentThread.getContextClassLoader();
            currentThread.setContextClassLoader(CrowdConfigurationService.class.getClassLoader());
        }
        try {
            return crowdClient.authenticateUser(login, password);
        } finally {
            if (currentThread != null) {
                currentThread.setContextClassLoader(orgContextClassLoader);
            }
        }
    }

    public User getUser(String username) throws UserNotFoundException, OperationFailedException,
            ApplicationPermissionException, InvalidAuthenticationException {
        // Load the entry from cache if it's valid return it
        User retval = getValidValueFromCache(username, userCache);
        if (retval != null) {
            LOG.log(Level.FINEST, "getUser() cache hit: {0}", username);
            return retval;
        }

        LOG.log(Level.FINEST, "getUser() cache hit MISS: {0}", username);

        ClassLoader orgContextClassLoader = null;
        Thread currentThread = null;
        if (IS_MIN_JAVA_11) {
            currentThread = Thread.currentThread();
            orgContextClassLoader = currentThread.getContextClassLoader();
            currentThread.setContextClassLoader(CrowdConfigurationService.class.getClassLoader());
        }
        try {
            retval = crowdClient.getUser(username);
        } finally {
            if (currentThread != null) {
                currentThread.setContextClassLoader(orgContextClassLoader);
            }
        }

        // If correct object was returned save it to cache
        // checking if key is present is redundant
        setValueToCache(username, retval, userCache);

        return retval;
    }

    public Group getGroup(String name) throws GroupNotFoundException, OperationFailedException,
            InvalidAuthenticationException, ApplicationPermissionException {
        // Load the entry from cache if it's valid return it
        Group retval = getValidValueFromCache(name, groupCache);
        if (retval != null) {
            LOG.log(Level.FINEST, "getGroup() cache hit: {0}", name);
            return retval;
        }

        LOG.log(Level.FINEST, "getGroup() cache hit MISS: {0}", name);

        LOG.log(Level.FINEST, "CrowdClient.getGroup()");

        ClassLoader orgContextClassLoader = null;
        Thread currentThread = null;
        if (IS_MIN_JAVA_11) {
            currentThread = Thread.currentThread();
            orgContextClassLoader = currentThread.getContextClassLoader();
            currentThread.setContextClassLoader(CrowdConfigurationService.class.getClassLoader());
        }
        try {
            retval = crowdClient.getGroup(name);
        } finally {
            if (currentThread != null) {
                currentThread.setContextClassLoader(orgContextClassLoader);
            }
        }

        // If correct object was returned save it to cache
        // checking if key is present is redundant
        setValueToCache(name, retval, groupCache);

        return retval;
    }

    public List<Group> getGroupsForNestedUser(String username, int start, int size)
            throws OperationFailedException, InvalidAuthenticationException, ApplicationPermissionException,
            UserNotFoundException {
        LOG.log(Level.FINEST, "CrowdClient.getGroupsForNestedUser()");
        ClassLoader orgContextClassLoader = null;
        Thread currentThread = null;
        if (IS_MIN_JAVA_11) {
            currentThread = Thread.currentThread();
            orgContextClassLoader = currentThread.getContextClassLoader();
            currentThread.setContextClassLoader(CrowdConfigurationService.class.getClassLoader());
        }
        try {
            return crowdClient.getGroupsForNestedUser(username, start, size);
        } finally {
            if (currentThread != null) {
                currentThread.setContextClassLoader(orgContextClassLoader);
            }
        }
    }

    public List<Group> getGroupsForUser(String username, int start, int size) throws OperationFailedException,
            InvalidAuthenticationException, ApplicationPermissionException, UserNotFoundException {
        LOG.log(Level.FINEST, "CrowdClient.getGroupsForUser()");
        ClassLoader orgContextClassLoader = null;
        Thread currentThread = null;
        if (IS_MIN_JAVA_11) {
            currentThread = Thread.currentThread();
            orgContextClassLoader = currentThread.getContextClassLoader();
            currentThread.setContextClassLoader(CrowdConfigurationService.class.getClassLoader());
        }
        try {
            return crowdClient.getGroupsForUser(username, start, size);
        } finally {
            if (currentThread != null) {
                currentThread.setContextClassLoader(orgContextClassLoader);
            }
        }
    }

    public boolean isUserDirectGroupMember(String username, String groupname)
            throws OperationFailedException, ApplicationPermissionException, InvalidAuthenticationException {
        LOG.log(Level.FINEST, "CrowdClient.isUserDirectGroupMember()");

        ClassLoader orgContextClassLoader = null;
        Thread currentThread = null;
        if (IS_MIN_JAVA_11) {
            currentThread = Thread.currentThread();
            orgContextClassLoader = currentThread.getContextClassLoader();
            currentThread.setContextClassLoader(CrowdConfigurationService.class.getClassLoader());
        }
        try {
            return crowdClient.isUserDirectGroupMember(username, groupname);
        } finally {
            if (currentThread != null) {
                currentThread.setContextClassLoader(orgContextClassLoader);
            }
        }
    }

    public boolean isUserNestedGroupMember(String username, String groupname)
            throws OperationFailedException, ApplicationPermissionException, InvalidAuthenticationException {
        LOG.log(Level.FINEST, "CrowdClient.isUserNestedGroupMember()");

        ClassLoader orgContextClassLoader = null;
        Thread currentThread = null;
        if (IS_MIN_JAVA_11) {
            currentThread = Thread.currentThread();
            orgContextClassLoader = currentThread.getContextClassLoader();
            currentThread.setContextClassLoader(CrowdConfigurationService.class.getClassLoader());
        }
        try {
            return crowdClient.isUserNestedGroupMember(username, groupname);
        } finally {
            if (currentThread != null) {
                currentThread.setContextClassLoader(orgContextClassLoader);
            }
        }
    }

    public void validateSSOAuthentication(String token, List<ValidationFactor> list)
            throws OperationFailedException, InvalidAuthenticationException, ApplicationPermissionException,
            InvalidTokenException {
        LOG.log(Level.FINEST, "CrowdClient.validateSSOAuthentication()");

        ClassLoader orgContextClassLoader = null;
        Thread currentThread = null;
        if (IS_MIN_JAVA_11) {
            currentThread = Thread.currentThread();
            orgContextClassLoader = currentThread.getContextClassLoader();
            currentThread.setContextClassLoader(CrowdConfigurationService.class.getClassLoader());
        }
        try {
            crowdClient.validateSSOAuthentication(token, list);
        } finally {
            if (currentThread != null) {
                currentThread.setContextClassLoader(orgContextClassLoader);
            }
        }
    }

    public User findUserFromSSOToken(String token) throws OperationFailedException, InvalidAuthenticationException,
            ApplicationPermissionException, InvalidTokenException {
        // Load the entry from cache if it's valid return it
        User retval = getValidValueFromCache(token, userFromSSOTokenCache);

        if (retval != null) {
            LOG.log(Level.FINEST, "findUserFromSSOToken() cache hit");
            return retval;
        }

        LOG.log(Level.FINEST, "findUserFromSSOToken() cache hit MISS");

        ClassLoader orgContextClassLoader = null;
        Thread currentThread = null;
        if (IS_MIN_JAVA_11) {
            currentThread = Thread.currentThread();
            orgContextClassLoader = currentThread.getContextClassLoader();
            currentThread.setContextClassLoader(CrowdConfigurationService.class.getClassLoader());
        }
        try {
            retval = crowdClient.findUserFromSSOToken(token);
        } finally {
            if (currentThread != null) {
                currentThread.setContextClassLoader(orgContextClassLoader);
            }
        }

        // If correct object was returned save it to cache
        // checking if key is present is redundant
        setValueToCache(token, retval, userFromSSOTokenCache);

        return retval;
    }

    public void shutdown() {
        LOG.log(Level.FINEST, "CrowdClient.shutdown()");

        ClassLoader orgContextClassLoader = null;
        Thread currentThread = null;
        if (IS_MIN_JAVA_11) {
            currentThread = Thread.currentThread();
            orgContextClassLoader = currentThread.getContextClassLoader();
            currentThread.setContextClassLoader(CrowdConfigurationService.class.getClassLoader());
        }
        try {
            crowdClient.shutdown();
        } finally {
            if (currentThread != null) {
                currentThread.setContextClassLoader(orgContextClassLoader);
            }
        }
    }

    public void testConnection()
            throws OperationFailedException, InvalidAuthenticationException, ApplicationPermissionException {
        ClassLoader orgContextClassLoader = null;
        Thread currentThread = null;
        if (IS_MIN_JAVA_11) {
            currentThread = Thread.currentThread();
            orgContextClassLoader = currentThread.getContextClassLoader();
            currentThread.setContextClassLoader(CrowdConfigurationService.class.getClassLoader());
        }
        LOG.log(Level.FINEST, "CrowdClient.testConnection()");

        try {
            crowdClient.testConnection();
        } finally {
            if (currentThread != null) {
                currentThread.setContextClassLoader(orgContextClassLoader);
            }
        }
    }

    public String getCrowdToken(HttpServletRequest httpServletRequest) {
        LOG.log(Level.FINEST, "TokenHelper.getCrowdToken()");
        return tokenHelper.getCrowdToken(httpServletRequest, clientProperties.getCookieTokenKey());
    }

    public List<ValidationFactor> getValidationFactors(HttpServletRequest request) {
        LOG.log(Level.FINEST, "TokenHelper.getValidationFactorExtractor().getValidationFactors()");
        return tokenHelper.getValidationFactorExtractor().getValidationFactors(request);
    }

    public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse)
            throws ApplicationPermissionException, InvalidAuthenticationException, OperationFailedException {
        LOG.log(Level.FINEST, "CrowdHttpAuthenticator.logout()");

        ClassLoader orgContextClassLoader = null;
        Thread currentThread = null;
        if (IS_MIN_JAVA_11) {
            currentThread = Thread.currentThread();
            orgContextClassLoader = currentThread.getContextClassLoader();
            currentThread.setContextClassLoader(CrowdConfigurationService.class.getClassLoader());
        }
        try {
            crowdHttpAuthenticator.logout(httpServletRequest, httpServletResponse);
        } finally {
            if (currentThread != null) {
                currentThread.setContextClassLoader(orgContextClassLoader);
            }
        }
    }

    public User authenticate(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
            String name,
            String credentials)
            throws ApplicationPermissionException, InvalidAuthenticationException, OperationFailedException,
            ApplicationAccessDeniedException, ExpiredCredentialException, InactiveAccountException,
            InvalidTokenException {
        LOG.log(Level.FINEST, "CrowdHttpAuthenticator.authenticate()");
        ClassLoader orgContextClassLoader = null;
        Thread currentThread = null;
        if (IS_MIN_JAVA_11) {
            currentThread = Thread.currentThread();
            orgContextClassLoader = currentThread.getContextClassLoader();
            currentThread.setContextClassLoader(CrowdConfigurationService.class.getClassLoader());
        }
        try {
            return crowdHttpAuthenticator.authenticate(httpServletRequest, httpServletResponse, name, credentials);
        } finally {
            if (currentThread != null) {
                currentThread.setContextClassLoader(orgContextClassLoader);
            }
        }
    }

    public boolean isAuthenticated(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse)
            throws OperationFailedException {
        LOG.log(Level.FINEST, "CrowdHttpAuthenticator.isAuthenticated()");
        ClassLoader orgContextClassLoader = null;
        Thread currentThread = null;
        if (IS_MIN_JAVA_11) {
            currentThread = Thread.currentThread();
            orgContextClassLoader = currentThread.getContextClassLoader();
            currentThread.setContextClassLoader(CrowdConfigurationService.class.getClassLoader());
        }
        try {
            return crowdHttpAuthenticator.checkAuthenticated(httpServletRequest, httpServletResponse).isAuthenticated();
        } finally {
            if (currentThread != null) {
                currentThread.setContextClassLoader(orgContextClassLoader);
            }
        }
    }

    /**
     * Checks whether the user is a member of the given Crowd group.
     *
     * @param username The name of the user to check. May not be <code>null</code>
     *                 or
     *                 empty.
     * @param group    The name of the group to check the user against. May not be
     *                 <code>null</code>.
     * @return <code>true</code> if and only if the group exists, is active and
     *         the user is either a direct group member or, if nested groups may
     *         be used, a nested group member. <code>false</code> else.
     * @throws ApplicationPermissionException If the application is not permitted to
     *                                        perform the requested
     *                                        operation on the server.
     * @throws InvalidAuthenticationException If the application and password are
     *                                        not valid.
     * @throws OperationFailedException       If the operation has failed for any
     *                                        other reason, including
     *                                        invalid arguments and the operation
     *                                        not being supported on
     *                                        the server.
     */
    private boolean isGroupMember(String username, String group)
            throws ApplicationPermissionException,
            InvalidAuthenticationException, OperationFailedException {
        boolean retval = false;
        if (isGroupActive(group)) {
            LOG.log(Level.FINE, "Checking group membership for user ''{0}'' and group ''{1}''...", new Object[] {username, group});

            if (this.nestedGroups) {
                if (isUserNestedGroupMember(username, group)) {
                    retval = true;
                    LOG.log(Level.FINER, "=> user is a nested group member");
                }
            } else {
                if (isUserDirectGroupMember(username, group)) {
                    retval = true;
                    LOG.log(Level.FINER, "=> user is a direct group member");
                }
            }
        }
        return retval;
    }

    private Properties getProperties(String url, String applicationName, Secret password,
            int sessionValidationInterval, boolean useSSO,
            String cookieDomain, String cookieTokenkey, Boolean useProxy,
            String httpProxyHost, String httpProxyPort, String httpProxyUsername,
            Secret httpProxyPassword, String socketTimeout,
            String httpTimeout, String httpMaxConnections) {
        // for
        // https://docs.atlassian.com/crowd/2.7.1/com/atlassian/crowd/service/client/ClientPropertiesImpl.html
        Properties props = new Properties();

        String crowdUrl = url;
        if (!crowdUrl.endsWith("/")) {
            crowdUrl += "/";
        }
        props.setProperty("application.name", applicationName);
        props.setProperty("application.password", password.getPlainText());
        props.setProperty("crowd.base.url", crowdUrl);
        props.setProperty("application.login.url", crowdUrl + "console/");
        props.setProperty("crowd.server.url", crowdUrl + "services/");
        props.setProperty("session.validationinterval", String.valueOf(sessionValidationInterval));
        // TODO move other values to jenkins web configuration
        props.setProperty("session.isauthenticated", "session.isauthenticated");
        props.setProperty("session.tokenkey", "session.tokenkey");
        props.setProperty("session.lastvalidation", "session.lastvalidation");

        if (useSSO) {
            if (cookieDomain != null && !cookieDomain.equals(""))
                props.setProperty("cookie.domain", cookieDomain);
            if (cookieTokenkey != null && !cookieTokenkey.equals(""))
                props.setProperty("cookie.tokenkey", cookieTokenkey);
        }

        if (useProxy != null && useProxy) {
            if (httpProxyHost != null && !httpProxyHost.equals(""))
                props.setProperty("http.proxy.host", httpProxyHost);
            if (httpProxyPort != null && !httpProxyPort.equals(""))
                props.setProperty("http.proxy.port", httpProxyPort);
            if (httpProxyUsername != null && !httpProxyUsername.equals(""))
                props.setProperty("http.proxy.username", httpProxyUsername);
            if (httpProxyPassword != null && !httpProxyPassword.getPlainText().equals(""))
                props.setProperty("http.proxy.password", httpProxyPassword.getPlainText());
        }

        if (socketTimeout != null && !socketTimeout.equals(""))
            props.setProperty("socket.timeout", socketTimeout);
        if (httpMaxConnections != null && !httpMaxConnections.equals(""))
            props.setProperty("http.max.connections", httpMaxConnections);
        if (httpTimeout != null && !httpTimeout.equals(""))
            props.setProperty("http.timeout", httpTimeout);

        return props;
    }

    private <V> V getValidValueFromCache(String key, Cache<String, V> cacheObj) {
        if (!useCache || cacheObj == null) {
            return null;
        }

        return cacheObj.getIfPresent(key);
    }

    private <V> void setValueToCache(String key, V value, Cache<String,V> cacheObj) {
        // Let's save the entry in the cache if necessary
        if (!useCache || value == null) {
            return;
        }

        cacheObj.put(key, value);
    }
}
