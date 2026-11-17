package org.keycloak.broker.bankid.model;

public class CompletionData {

	BankidUser user;

	BankidDevice device;

	String bankIdIssueDate;

	StepUp stepUp;

	String signature;

	String ocspResponse;

	String risk;

	public BankidUser getUser() {
		return user;
	}

	public void setUser(BankidUser user) {
		this.user = user;
	}

	public BankidDevice getDevice() {
		return device;
	}

	public void setDevice(BankidDevice device) {
		this.device = device;
	}

	public String getBankIdIssueDate() {
		return bankIdIssueDate;
	}

	public void setBankIdIssueDate(String bankIdIssueDate) {
		this.bankIdIssueDate = bankIdIssueDate;
	}

	public StepUp getStepUp() {
		return stepUp;
	}

	public void setStepUp(StepUp stepUp) {
		this.stepUp = stepUp;
	}

	public String getSignature() {
		return signature;
	}

	public void setSignature(String signature) {
		this.signature = signature;
	}

	public String getOcspResponse() {
		return ocspResponse;
	}

	public void setOcspResponse(String ocspResponse) {
		this.ocspResponse = ocspResponse;
	}

	/** low, medium or high; present only when the order asked for it with returnRisk. */
	public String getRisk() {
		return risk;
	}

	public void setRisk(String risk) {
		this.risk = risk;
	}
}
