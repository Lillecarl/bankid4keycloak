package org.keycloak.broker.bankid.model;

public enum BankidHintCodes {
	// Pending
	outstandingTransaction("RFA1"),
	noClient("RFA1"),
	started("RFA14B"),
	userSign("RFA9"),

	// 400 Error codes
	alreadyInProgress("RFA4"),
	invalidParameters("RFA22"),

	// 503 Error codes
	Maintenance("RFA5"),

	// Errors
	internalError("RFA5"),
	expiredTransaction("RFA8"),
	certificateErr("RFA16"),
	userCancel("RFA6"),
	cancelled("RFA3"),
	startFailed("RFA17A"),
	unkown("RFA22"),

	// Internal error (by the BankID IDP Provider)
	internal("RFA22");

	public final String messageShortName;

	private BankidHintCodes(String messageShortName) {
		this.messageShortName = messageShortName;
	}

	/** The hint for a code from BankID or the browser; an unknown code, null included, maps to {@link #unkown}. */
	public static BankidHintCodes of(String code) {
		if (code != null) {
			for (BankidHintCodes hint : values()) {
				if (hint.name().equals(code)) {
					return hint;
				}
			}
		}
		return unkown;
	}
}
