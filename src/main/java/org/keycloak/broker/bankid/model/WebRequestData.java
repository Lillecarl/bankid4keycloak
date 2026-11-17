package org.keycloak.broker.bankid.model;

/**
 * The {@code web} member of an order: facts about the browser that starts
 * it. BankID uses them, among other things, for the risk indication.
 */
public class WebRequestData {

	private String referringDomain;
	private String userAgent;
	private String deviceIdentifier;

	public String getReferringDomain() {
		return referringDomain;
	}

	public void setReferringDomain(String referringDomain) {
		this.referringDomain = referringDomain;
	}

	public String getUserAgent() {
		return userAgent;
	}

	public void setUserAgent(String userAgent) {
		this.userAgent = userAgent;
	}

	public String getDeviceIdentifier() {
		return deviceIdentifier;
	}

	public void setDeviceIdentifier(String deviceIdentifier) {
		this.deviceIdentifier = deviceIdentifier;
	}
}
