package de.theit.jenkins.crowd;

import com.atlassian.crowd.model.authentication.ValidationFactor;

import java.io.Serializable;
import java.util.List;

public class CrowdSSOAuthenticationDetails implements Serializable {
	private final String applicationName;
	private final List<ValidationFactor> validationFactors;

	public CrowdSSOAuthenticationDetails(String applicationName, List<ValidationFactor> validationFactors)
	{
		this.applicationName = applicationName;
		this.validationFactors = validationFactors;
	}

	public String getApplicationName()
	{
		return this.applicationName;
	}

	public List<ValidationFactor> getValidationFactorsList(){
		return this.validationFactors;
	}

	public ValidationFactor[] getValidationFactors() {
		return (ValidationFactor[]) this.validationFactors.toArray();
	}

	public boolean equals(Object o)
	{
		if (this == o) return true;
		if ((o == null) || (getClass() != o.getClass())) return false;

		CrowdSSOAuthenticationDetails that = (CrowdSSOAuthenticationDetails)o;

		if (this.applicationName != null ? !this.applicationName.equals(that.applicationName) : that.applicationName != null)
			return false;
		if (!this.validationFactors.equals(that.validationFactors)) return false;

		return true;
	}

	public int hashCode()
	{
		int result = this.applicationName != null ? this.applicationName.hashCode() : 0;
		result = 31 * result + (this.validationFactors != null ? this.validationFactors.hashCode() : 0);
		return result;
	}
}
