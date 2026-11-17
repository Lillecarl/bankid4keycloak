package org.keycloak.broker.bankid;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

import jakarta.ws.rs.core.Response;

import org.keycloak.broker.bankid.client.SimpleBankidClient;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;

public class BankidIdentityProvider extends AbstractIdentityProvider<BankidIdentityProviderConfig> {

	/** User attributes written when the username is a pseudonym; the names match the Freja eID provider's. */
	public static final String ATTR_PERSONAL_NUMBER = "personalIdentityNumber";
	public static final String ATTR_PERSONAL_NUMBER_COUNTRY = "personalIdentityNumberCountry";
	static final String CONTEXT_PERSONAL_NUMBER = "bankid.personalIdentityNumber";

	private final SimpleBankidClient bankidClient;

	public BankidIdentityProvider(KeycloakSession session, BankidIdentityProviderConfig config,
			SimpleBankidClient bankidClient) {
		super(session, config);
		this.bankidClient = bankidClient;
	}

	@Override
	public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
		return new BankidEndpoint(this, getConfig(), callback);
	}

	@Override
	public Response performLogin(AuthenticationRequest request) {
		try {
			return Response.status(302)
					.location(new URI(request.getRedirectUri() + "/start?state=" + request.getState().getEncoded()))
					.build();
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException();
		}
	}

	public KeycloakSession getSession() {
		return this.session;
	}

	@Override
	public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
		return Response.ok(identity.getToken()).build();
	}

	// The Identity Brokering API v2 (POST .../token) calls this, from Keycloak
	// 26.6; no @Override, so the class still compiles against 26.5. BankID
	// gives no token to store, so the answer is the JSON error SAML's provider
	// gives when it holds none.
	public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity,
			UserSessionModel userSession, UserModel user) {
		return exchangeErrorResponse(session.getContext().getUri(), null, userSession,
				"token_expired", "No token stored.");
	}

	@Override
	public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm,
			BrokeredIdentityContext context) {
		context.getContextData().putAll(context.getAuthenticationSession().getUserSessionNotes());
	}

	@Override
	public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user,
			BrokeredIdentityContext context) {
		// Here context.getAuthenticationSession().getUserSessionNotes() is empty
		// use context data to retrieve information stored in {@link BankidIdentProvider#preprocessFederatedIdentity()}
		Map<String, Object> contextData = context.getContextData();
		// Iterate over the context data to extract the required information:
		for (Map.Entry<String, Object> entry : contextData.entrySet()) {
			String key = entry.getKey();
			// Add the value to the user session notes if key starts with provider config
			// alias since it means it was added by the BankidEndpoint
			// The personal number goes to the user attribute only, never into a
			// session note, even when the alias is a prefix of its key.
			if (key.startsWith(this.getConfig().getAlias()) && !CONTEXT_PERSONAL_NUMBER.equals(key)) {
				Object value = entry.getValue();
				context.getAuthenticationSession().setUserSessionNote(key, value.toString());
			}
		}
		writeAttributes(user, context);
	}

	@Override
	public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user,
			BrokeredIdentityContext context) {
		writeAttributes(user, context);
	}

	private static void writeAttributes(UserModel user, BrokeredIdentityContext context) {
		Object personalNumber = context.getContextData().get(CONTEXT_PERSONAL_NUMBER);
		if (personalNumber != null) {
			user.setSingleAttribute(ATTR_PERSONAL_NUMBER, personalNumber.toString());
			user.setSingleAttribute(ATTR_PERSONAL_NUMBER_COUNTRY, "SE");
		}
	}

	public SimpleBankidClient getBankidClient() {
		return bankidClient;
	}

}
