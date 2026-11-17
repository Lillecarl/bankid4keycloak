package org.keycloak.broker.bankid.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

// BankID adds response fields without notice and says a client must accept them.
@JsonIgnoreProperties(ignoreUnknown = true)
public class BankidDevice {

	String ipAddress;

	String uhi;

	public String getIpAddress() {
		return ipAddress;
	}

	public void setIpAddress(String ipAddress) {
		this.ipAddress = ipAddress;
	}

	public String getUhi() {
		return uhi;
	}

	public void setUhi(String uhi) {
		this.uhi = uhi;
	}
}
