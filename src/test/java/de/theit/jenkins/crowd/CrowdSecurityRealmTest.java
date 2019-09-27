package de.theit.jenkins.crowd;

import com.atlassian.crowd.integration.rest.service.factory.RestCrowdClientFactory;
import com.atlassian.crowd.service.client.CrowdClient;
import hudson.util.FormValidation;
import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

public class CrowdSecurityRealmTest {
    @Rule public JenkinsRule j = new JenkinsRule();
    @Mock public RestCrowdClientFactory restCrowdClientFactory;
    @Mock public CrowdClient crowdClient;

    @Before public void setup() {
        MockitoAnnotations.initMocks(this);
    }

    // We expect a stack trace in the test logs for the connection issue
    // But we don't want a JAXB related issue, which will mark the test as failed.
    @Issue("JENKINS-59301")
    @Test
    public void shouldBeAbleToValidateConnection() throws Exception {
        // given
        CrowdSecurityRealm.DescriptorImpl descriptor = new CrowdSecurityRealm.DescriptorImpl();
        // when
        Mockito.when(restCrowdClientFactory.newInstance(Mockito.any())).thenReturn(crowdClient);
        FormValidation validation = descriptor.doTestConnection(
                    "http://localhost/",
                    "example",
                    "",
                    "",
                    false,
                    "",
                    1,
                    "",
                    false,
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    ""
              );
        // then
        Assertions.assertThat(validation.kind).isEqualByComparingTo(FormValidation.Kind.ERROR);
    }
}
