package de.theit.jenkins.crowd;

import hudson.Extension;
import hudson.model.User;
import org.apache.commons.lang.StringUtils;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Attempts to resolve a Crowd plugin user Id in the form of "{@code FULL NAME (username)}" where {@code username} is
 * the actual user Id.
 *
 * @author jstiefel
 */
@Extension
public class CrowdCanonicalEmbeddedIdResolver extends User.CanonicalIdResolver {

    /**
     * Matches the {@link CrowdAuthenticationToken#getName()} pattern of "{@code FULL NAME (username)}"
     */
    public static final Pattern EMBEDDED_ID_REGEX = Pattern.compile("^\\s*?.+\\((.+?)\\).*$");

    @Override
    public String resolveCanonicalId(String idOrFullName, Map<String, ?> context) {

        if (StringUtils.isBlank(idOrFullName))
            return idOrFullName;

        Matcher m = EMBEDDED_ID_REGEX.matcher(idOrFullName);
        if (!m.matches())
            return idOrFullName;

        return m.group(1);
    }
}
