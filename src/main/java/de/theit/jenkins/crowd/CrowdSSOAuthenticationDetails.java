package de.theit.jenkins.crowd;

import com.atlassian.crowd.model.authentication.ValidationFactor;

import java.io.Serializable;
import java.util.List;

/**
 * CrowdSSOAuthenticationDetails that contains application name and Crowd Validation factors
 */
public class CrowdSSOAuthenticationDetails implements Serializable {
    private final String applicationName;
    // can be null??
    private final List<ValidationFactor> validationFactors;

    public CrowdSSOAuthenticationDetails(String applicationName, List<ValidationFactor> validationFactors) {
        this.applicationName = applicationName;
        this.validationFactors = validationFactors;
    }

    public String getApplicationName() {
        return applicationName;
    }

    public List<ValidationFactor> getValidationFactorsList(){
        return validationFactors;
    }

    public ValidationFactor[] getValidationFactors() {
        return validationFactors.toArray(new ValidationFactor[validationFactors.size()]);
    }

    public boolean equals(Object o) {
        if (this == o) return true;
        if ((o == null) || (getClass() != o.getClass())) return false;

        CrowdSSOAuthenticationDetails that = (CrowdSSOAuthenticationDetails)o;

        if (this.applicationName != null ? !this.applicationName.equals(that.applicationName)
                : that.applicationName != null) {
            return false;
        }

        return this.validationFactors.equals(that.validationFactors);
    }

    public int hashCode() {
        int result = this.applicationName != null ? this.applicationName.hashCode() : 0;
        result = 31 * result + (this.validationFactors != null ? this.validationFactors.hashCode() : 0);
        return result;
    }
}
