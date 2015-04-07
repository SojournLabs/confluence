/**
 * Author: jonathan lung <lungj@sojournlabs.com>
 * Copyright 2015 jonathan lung
 * 
 * Authentication class for Confluence that uses client certificates forwarded by a proxy.
 * Compiled against Confluence 5.6.4 libs using
 *     javac CertAuthenticator.java -cp /var/confluence/install/confluence/WEB-INF/lib/log4j-1.2.15.jar:/var/confluence/install/confluence/WEB-INF/lib/atlassian-seraph-3.0.0.jar:/var/confluence/install/lib/servlet-api.jar:/var/confluence/install/confluence/WEB-INF/lib/confluence-5.6.4.jar:/var/confluence/install/confluence/WEB-INF/lib/atlassian-user-3.0.jar:/var/confluence/install/confluence/WEB-INF/lib/crowd-api-2.7.1.jar:/var/confluence/install/confluence/WEB-INF/lib/atlassian-plugins-osgi-3.2.8.jar:/var/confluence/install/confluence/WEB-INF/lib/atlassian-spring-2.0.0.jar:/var/confluence/install/confluence/WEB-INF/lib/embedded-crowd-api-2.7.1.jar:/var/confluence/install/confluence/WEB-INF/lib/embedded-crowd-spi-2.7.1.jar:/var/confluence/install/confluence/WEB-INF/lib/embdded-crowd-core-2.7.1.jar:/var/confluence/install/confluence/WEB-INF/lib/crowd-integration-api-2.7.1.jar
 */
package com.sojournlabs;
import org.apache.log4j.Category;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.atlassian.confluence.user.ConfluenceAuthenticator;
import com.atlassian.crowd.embedded.api.CrowdService;
import com.atlassian.crowd.model.user.UserTemplate;
import com.atlassian.seraph.auth.AuthenticatorException;
import com.atlassian.seraph.auth.DefaultAuthenticator;
import com.atlassian.spring.container.ContainerManager;

import java.security.Principal;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extension of DefaultAuthenticator that uses third-party code to determine if a user is logged in,
 * given a HTTPRequest object.
 * Third-party code will typically check for the existence of a special cookie.
 * 
 * In SSO scenarios where this authenticator is used, one typically configures Seraph to use an external login page
 * as well:
 * 
 *  <init-param>
 *    <param-name>login.url</param-name>
 *    <param-value>http://mycompany.com/globallogin?target=${originalurl}</param-value>
 *  </init-param>
 *
 */
public class CertAuthenticator extends ConfluenceAuthenticator {
    private static final Category log = Category.getInstance(CertAuthenticator.class);

    public Principal getUser(HttpServletRequest request, HttpServletResponse response) {
        Principal user = null;

        try {
            if(request.getSession() != null && request.getSession().getAttribute(DefaultAuthenticator.LOGGED_IN_KEY) != null) {
                return (Principal) request.getSession().getAttribute(DefaultAuthenticator.LOGGED_IN_KEY);
            } else {
            	String cert = request.getHeader("x-ssl-cn-s");
            	
            	if (cert == null) {
            	    log.info("No certificate provided.");
            	    return user;
            	}

            	Pattern pat = Pattern.compile("/CN=([^/]+)/emailAddress=(([^@]+)@.*)");
            	Matcher matcher = pat.matcher(request.getHeader("x-ssl-cn-s"));

            	if (!matcher.find()) {
            		log.info("Invalid CN");
            		return user;
            	}
            	
            	log.info("Full match: " + matcher.group(0));
            	String name = matcher.group(1);
            	String username = matcher.group(3);
            	String email = matcher.group(2);
            	
            	log.info("Fetching " + username);

            	user = (Principal) getUser(username);
            	if (user == null) {
            		log.info("Creating " + username);
            		UserTemplate template = new UserTemplate(username);
            		template.setDisplayName(name);
            		template.setEmailAddress(email);
            		CrowdService cser = (CrowdService) ContainerManager.getComponent("crowdService");
            		cser.addUser(template, "password");
            		user = (Principal) getUser(username);
            	}
            	if (user != null) {
	            	putPrincipalInSessionContext(request, user);
	            	getElevatedSecurityGuard().onSuccessfulLoginAttempt(request, username);
	            	
	            	request.getSession().setAttribute(DefaultAuthenticator.LOGGED_IN_KEY, user);
	                request.getSession().setAttribute(DefaultAuthenticator.LOGGED_OUT_KEY, null);
	                log.info(String.format("Login for user %s successful.", username));
	                return user;
            	}
            }
        } catch (Exception e) {
            log.warn("Exception: " + e, e);
        }

        log.info(String.format("Login failed."));
        return null;
    }
}
