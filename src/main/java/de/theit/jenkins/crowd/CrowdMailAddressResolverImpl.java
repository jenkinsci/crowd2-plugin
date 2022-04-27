/*
 * @(#)CrowdMailAddressResolverImpl.java
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

import hudson.Extension;
import hudson.model.User;
import hudson.security.SecurityRealm;
import hudson.security.UserMayOrMayNotExistException2;
import hudson.tasks.MailAddressResolver;
import jenkins.model.Jenkins;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.springframework.security.core.userdetails.UsernameNotFoundException;


/**
 * This class resolves email addresses via lookup in Crowd.
 *
 * @author <a href="mailto:theit@gmx.de">Thorsten Heit (theit@gmx.de)</a>
 * @since 08.09.2011
 * @version $Id$
 */
@Extension
public class CrowdMailAddressResolverImpl extends MailAddressResolver {
    /** For logging purposes. */
    private static final Logger LOG = Logger.getLogger(CrowdMailAddressResolverImpl.class.getName());

    /**
     * {@inheritDoc}
     *
     * @see hudson.tasks.MailAddressResolver#findMailAddressFor(hudson.model.User)
     */
    @Override
    public String findMailAddressFor(User u) {
        String mail = null;
        SecurityRealm realm = getSecurityRealm();

        if (realm instanceof CrowdSecurityRealm) {
            try {
                String userId = u.getId();
                LOG.log(Level.FINE, "Looking up mail address for user: {0}", userId);
                CrowdUser details = (CrowdUser) realm.loadUserByUsername2(userId);
                mail = details.getEmailAddress();
            } catch (UserMayOrMayNotExistException2  ex) {
                LOG.log(Level.SEVERE, "User do not exist, unable to look up email address", ex);
            } catch (UsernameNotFoundException ex) {
                LOG.log(Level.INFO, "Failed to look up email address in Crowd");
            }
        }

        return mail;
    }

    /**
     * Gets the user id from display name.
     *
     * This is a workaround.
     * The user object given as parameter contains the user's
     * display name. Looking up a user in Crowd by the full display
     * name doesn't work; we have to use the user's Id instead which
     * is actually appended at the end of the display name in brackets
     *
     * @param user the user
     * @return the user id from display name
     */
    String getUserIdFromDisplayName(User user) {
        String userId = user.getDisplayName();
        int pos = userId.lastIndexOf('(');
        if (pos > 0) {
            int pos2 = userId.indexOf(')', pos + 1);
            if (pos2 > pos) {
                userId = userId.substring(pos + 1, pos2);
            }
        }
        return userId;
    }

    SecurityRealm getSecurityRealm() {
        return Jenkins.get().getSecurityRealm();
    }
}
