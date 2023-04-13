/*
 * @(#)ErrorMessages.java
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

import java.util.List;

import org.jvnet.localizer.ResourceBundleHolder;

/**
 * This class delivers localized error messages.
 *
 * @author <a href="mailto:theit@gmx.de">Thorsten Heit (theit@gmx.de)</a>
 * @since 06.09.2011
 * @version $Id$
 */
public class ErrorMessages {
    /** Contains the localized messages. */
    private static final ResourceBundleHolder holder = ResourceBundleHolder.get(ErrorMessages.class);

    /**
     * Returns the localized error message when no URL is specified.
     *
     * @return The localized error message for a missing Crowd URL.
     */
    public static String specifyCrowdUrl() {
        return holder.format("pleaseSpecifyCrowdUrl");
    }

    /**
     * Returns the localized error message when no application name is given.
     *
     * @return The localized error message for a missing application name.
     */
    public static String specifyApplicationName() {
        return holder.format("specifyApplicationName");
    }

    /**
     * Returns the localized error message when no application password is
     * given.
     *
     * @return The localized error message for a missing application password.
     */
    public static String specifyApplicationPassword() {
        return holder.format("specifyApplicationPassword");
    }

    /**
     * Returns the localized error message when no group name is given.
     *
     * @return The localized error message for a missing group name.
     */
    public static String specifyGroup() {
        return holder.format("specifyGroup");
    }

    /**
     * Returns the localized error message when no session validation interval
     * time is given.
     *
     * @return The localized error message for a missing session validation
     *         interval time.
     */
    public static String specifySessionValidationInterval() {
        return holder.format("specifySessionValidationInterval");
    }

    /**
     * Returns the localized error message when the connection check failed.
     *
     * @return The localized error message for a failed connection check.
     */
    public static String operationFailed() {
        return holder.format("operationFailed");
    }

    /**
     * Returns the localized error message when the configuration file
     * crowd.properties cannot be loaded.
     *
     * @return The localized error message when the configuration file
     *         crowd.properties cannot be loaded.
     */
    public static String cannotLoadCrowdProperties() {
        return holder.format("cannotLoadCrowdProperties");
    }

    /**
     * Returns the localized error message text when the application name and
     * password are not valid.
     *
     * @return The localized error message for invalid application name and
     *         password.
     */
    public static String invalidAuthentication() {
        return holder.format("invalidAuthentication");
    }

    /**
     * Returns the localized error message text when the SSO authentication
     * token is not valid.
     *
     * @return The localized error message for invalid SSO authentication
     *         token.
     */
    public static String invalidToken() {

        return holder.format("invalidToken", "<HIDDEN>");
    }    

    /**
     * Returns the localized error message when the application has no
     * permission to perform a connection check to the Crowd server.
     *
     * @return The localized error message for missing permission to perform a
     *         connection check to the Crowd server.
     */
    public static String applicationPermission() {
        return holder.format("applicationPermission");
    }

    /**
     * Returns the localized error message when the user was not found on the
     * remote Crowd server.
     *
     * @param username The user name. May not be <code>null</code>.
     *
     * @return The localized error message when the user was not found on the
     *         remote Crowd server.
     */
    public static String userNotFound(String username) {
        return holder.format("userNotFound", username);
    }

    /**
     * Returns the localized error message when the group was not found on the
     * remote Crowd server.
     *
     * @param groupname The name of the group. May not be <code>null</code>.
     *
     * @return The localized error message when the group was not found on the
     *         remote Crowd server.
     */
    public static String groupNotFound(String groupname) {
        return holder.format("groupNotFound", groupname);
    }

    /**
     * Returns the localized error message when the user password has expired
     * and must be changed.
     *
     * @param username The user name. May not be <code>null</code>.
     *
     * @return The localized error message when the user password has expired.
     */
    public static String expiredCredentials(String username) {
        return holder.format("expiredCredentials", username);
    }

    /**
     * Returns the localized error message when the account is inactive.
     *
     * @param username The user name. May not be <code>null</code>.
     *
     * @return The localized error message when the account is inactive.
     */
    public static String accountExpired(String username) {
        return holder.format("accountExpired", username);
    }

    /**
     * Returns the localized error message when a user does not have access to
     * authenticate against an application.
     *
     * @param username The user name. May not be <code>null</code>.
     *
     * @return The localized error message for denied application access.
     */
    public static String applicationAccessDenied(String username) {
        return holder.format("applicationAccessDenied", username);
    }

    /**
     * Returns the localized error message when a user does not have the
     * permission to login.
     *
     * @param username   The user name. May not be <code>null</code>.
     * @param groupNames The names of the groups allowed to login. May not be
     *                   <code>null</code>.
     *
     * @return The localized error message when a user does not have the
     *         permission to login.
     */
    public static String userNotValid(String username, List<String> groupNames) {
        return holder.format("userNotValid", username, groupNames.toString());
    }
}
