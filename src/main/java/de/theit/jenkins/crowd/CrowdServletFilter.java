/*
  * @(#)CrowdServletFilter.java
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

import com.atlassian.crowd.exception.OperationFailedException;
import hudson.security.AuthenticationProcessingFilter2;
import org.acegisecurity.context.SecurityContext;
import org.acegisecurity.context.SecurityContextHolder;

import javax.servlet.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.logging.Logger;

import static org.acegisecurity.ui.rememberme.TokenBasedRememberMeServices.ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE_KEY;

/**
* Created with IntelliJ IDEA.
* User: integer
* Date: 5/11/14
* Time: 15:37
*/
public class CrowdServletFilter extends AuthenticationProcessingFilter2 {

    private static final Logger LOG = Logger.getLogger(CrowdServletFilter.class.getName());

    final CrowdSecurityRealm realm;
    CrowdConfigurationService configuration;
    private final Filter filter;

    public CrowdServletFilter(CrowdSecurityRealm realm, CrowdConfigurationService configuration, Filter filter){
        this.realm = realm;
        this.configuration = configuration;
        this.filter = filter;
    }

//    @Override
//    public Authentication attemptAuthentication(HttpServletRequest request)
//            throws AuthenticationException {
//		LOG.info("attemptAuthentication()");
//        System.out.println("attemptAuthentication()");
//        String username = obtainUsername(request);
//        String password = obtainPassword(request);
//
//        if (username == null) {
//            username = "";
//        }
//
//        if (password == null) {
//            password = "";
//        }
//
//        // create the list of granted authorities
//        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
//        // add the "authenticated" authority to the list of granted
//        // authorities...
//        authorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
//        // ..and all authorities retrieved from the Crowd server
//        authorities.addAll(configuration.getAuthoritiesForUser(username));
//
//        CrowdAuthenticationToken authRequest = new CrowdAuthenticationToken(username,
//                password,
//                authorities,
//                null);
//
//        // Place the last username attempted into HttpSession for views
//        request.getSession().setAttribute(ACEGI_SECURITY_LAST_USERNAME_KEY, username);
//
//        // Allow subclasses to set the "details" property
//        setDetails(request, authRequest);
//        SecurityContextHolder.getContext().setAuthentication(authRequest);
//        return this.getAuthenticationManager().authenticate(authRequest);
//    }

    private void setDetails(HttpServletRequest request, CrowdAuthenticationToken authRequest) {
        LOG.info("in setDetails() filter");
    }

    /**
     * {@inheritDoc}
     *
     * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest,
     *      javax.servlet.ServletResponse, javax.servlet.FilterChain)
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
        if (this.configuration.useSSO && request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
            HttpServletRequest req = (HttpServletRequest) request;
            HttpServletResponse res = (HttpServletResponse) response;

            // check if we have a token
            // if it is not present, we are not / no longer authenticated
            boolean isValidated = false;
            try {
                isValidated = configuration.crowdHttpAuthenticator.isAuthenticated(req, res);
            } catch (OperationFailedException ex) {
                LOG.info("failed OperationFailedException" + ex.toString());
            }

            if (!isValidated) {
				LOG.info("User is not logged in (anymore) via Crowd => logout user");
                SecurityContext sc = SecurityContextHolder.getContext();
                sc.setAuthentication(null);

                // invalidate the current session
                // (see SecurityRealm#doLogout())
                HttpSession session = req.getSession(false);
                if (session != null) {
                    session.invalidate();
                }
                SecurityContextHolder.clearContext();

                // reset remember-me cookie
                Cookie cookie = new Cookie(ACEGI_SECURITY_HASHED_REMEMBER_ME_COOKIE_KEY, "");
                cookie.setPath(req.getContextPath().length() > 0 ? req.getContextPath() : "/");
                res.addCookie(cookie);
            }
        }

        this.filter.doFilter(request, response, chain);
    }
}
