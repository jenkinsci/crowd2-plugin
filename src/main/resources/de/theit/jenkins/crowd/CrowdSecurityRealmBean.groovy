package de.theit.jenkins.crowd

import de.theit.jenkins.crowd.CrowdAuthenticationProvider
import de.theit.jenkins.crowd.CrowdConfigurationService
import de.theit.jenkins.crowd.CrowdUserDetailsService
import jenkins.model.Jenkins
import org.acegisecurity.providers.ProviderManager
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationProvider
import org.acegisecurity.providers.rememberme.RememberMeAuthenticationProvider


/*
   The 'instance' object refers to the instance of CrowdSecurityRealm
*/

crowdConfigurationService(CrowdConfigurationService, instance.group, instance.nestedGroups)

crowdUserDetailsService(CrowdUserDetailsService, crowdConfigurationService)
crowdAuthenticationProvider(CrowdAuthenticationProvider, crowdConfigurationService)

authenticationManager(ProviderManager) {
    providers = [
            crowdAuthenticationProvider,

            // these providers apply everywhere
            bean(RememberMeAuthenticationProvider) {
                key = Jenkins.getInstance().getSecretKey();
            },
            // this doesn't mean we allow anonymous access.
            // we just authenticate anonymous users as such,
            // so that later authorization can reject them if so configured
            bean(AnonymousAuthenticationProvider) {
                key = "anonymous"
            }
    ]
}
