package org.keycloak.broker.bankid;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.jboss.logging.Logger;
import org.keycloak.broker.bankid.client.BankidClientException;
import org.keycloak.broker.bankid.client.SimpleBankidClient;
import org.keycloak.broker.bankid.model.AuthResponse;
import org.keycloak.broker.bankid.model.BankidHintCodes;
import org.keycloak.broker.bankid.model.BankidUser;
import org.keycloak.broker.bankid.model.CollectResponse;
import org.keycloak.broker.bankid.model.CompletionData;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider.AuthenticationCallback;
import org.keycloak.broker.provider.util.IdentityBrokerState;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.CacheControl;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

/**
 * The login pages and the calls they make, under
 * /realms/{realm}/broker/{alias}/endpoint.
 *
 * The BankID order lives in the login's authentication session, as auth notes:
 * replicated across the Keycloak cluster, gone with the session, and bound to
 * the browser that holds the session cookie. Every call finds the session from
 * the cookie and the tab id inside {@code state}. Only {@code done} verifies the
 * state's session code, because verifying consumes it.
 */
public class BankidEndpoint {

	private static final Logger logger = Logger.getLogger(BankidEndpoint.class);

	private static final String NOTE = "bankid.";
	private static final String ORDER_REF = NOTE + "orderRef";
	private static final String AUTO_START_TOKEN = NOTE + "autoStartToken";
	private static final String QR_START_TOKEN = NOTE + "qrStartToken";
	private static final String QR_START_SECRET = NOTE + "qrStartSecret";
	private static final String STARTED = NOTE + "started";
	private static final String PERSONAL_NUMBER = NOTE + "personalNumber";
	private static final String COMPLETION = NOTE + "completion";
	// The alias of the provider that started the order. The other notes are
	// shared by every BankID provider of the realm.
	private static final String PROVIDER = NOTE + "provider";
	private static final String[] NOTES = { ORDER_REF, AUTO_START_TOKEN, QR_START_TOKEN, QR_START_SECRET, STARTED,
			PERSONAL_NUMBER, COMPLETION };

	private static final Pattern PERSONAL_NUMBER_FORMAT = Pattern.compile("(19|20)[0-9]{10}");
	private static final String QR_CODE_PREFIX = "bankid.";
	private static final int QR_CODE_SIZE = 246;

	private final BankidIdentityProviderConfig config;
	private final AuthenticationCallback callback;
	private final BankidIdentityProvider provider;
	private final SimpleBankidClient bankidClient;
	private final KeycloakSession session;

	public BankidEndpoint(BankidIdentityProvider provider, BankidIdentityProviderConfig config,
			AuthenticationCallback callback) {
		this.config = config;
		this.callback = callback;
		this.provider = provider;
		this.bankidClient = provider.getBankidClient();
		this.session = provider.getSession();
	}

	@GET
	@Path("/start")
	public Response start(@QueryParam("state") String state) {
		AuthenticationSessionModel authSession = authSession(state);
		if (authSession == null) {
			return noSession();
		}
		if (config.isRequiredNin()) {
			return form(authSession)
					.setAttribute("state", state)
					.createForm("start-bankid.ftl");
		}
		return doLogin(authSession, null, state);
	}

	@POST
	@Path("/login")
	public Response loginPost(@FormParam("nin") String nin, @FormParam("state") String state) {
		AuthenticationSessionModel authSession = authSession(state);
		if (authSession == null) {
			return noSession();
		}
		if (config.isRequiredNin() && (nin == null || !PERSONAL_NUMBER_FORMAT.matcher(nin).matches())) {
			return form(authSession)
					.setAttribute("state", state)
					.setError("bankid.hint.LOCAL1")
					.createForm("start-bankid.ftl");
		}
		return doLogin(authSession, config.isRequiredNin() ? nin : null, state);
	}

	@GET
	@Path("/login")
	public Response loginGet(@QueryParam("state") String state) {
		AuthenticationSessionModel authSession = authSession(state);
		if (authSession == null) {
			return noSession();
		}
		if (config.isRequiredNin()) {
			return start(state);
		}
		return doLogin(authSession, null, state);
	}

	private Response doLogin(AuthenticationSessionModel authSession, String nin, String state) {
		cancelRunning(authSession);
		clear(authSession);
		AuthResponse authResponse;
		try {
			authResponse = bankidClient.sendAuth(nin, session.getContext().getConnection().getRemoteAddr());
		} catch (BankidClientException e) {
			return error(e.getHintCode());
		}
		authSession.setAuthNote(ORDER_REF, authResponse.getOrderRef());
		authSession.setAuthNote(AUTO_START_TOKEN, authResponse.getAutoStartToken());
		authSession.setAuthNote(QR_START_TOKEN, authResponse.getQrStartToken());
		authSession.setAuthNote(QR_START_SECRET, authResponse.getQrStartSecret());
		authSession.setAuthNote(STARTED, Long.toString(authResponse.getAuthTimestamp()));
		authSession.setAuthNote(PROVIDER, config.getAlias());
		if (nin != null) {
			authSession.setAuthNote(PERSONAL_NUMBER, nin);
		}
		return form(authSession)
				.setAttribute("state", state)
				.setAttribute("autoStartToken", authResponse.getAutoStartToken())
				.setAttribute("showqr", config.isShowQRCode())
				.setAttribute("ninRequired", config.isRequiredNin())
				.createForm("login-bankid.ftl");
	}

	/**
	 * Polls BankID for the order and answers the page with its status. A
	 * complete order is kept only when it names the person the order asked for.
	 */
	@GET
	@Path("/collect")
	public Response collect(@QueryParam("state") String state) {
		AuthenticationSessionModel authSession = authSession(state);
		if (authSession == null || authSession.getAuthNote(ORDER_REF) == null) {
			return collectAnswer(Status.BAD_REQUEST, "failed", BankidHintCodes.internal.name());
		}
		if (!startedHere(authSession)) {
			return collectAnswer(Status.BAD_REQUEST, "failed", BankidHintCodes.internal.name());
		}
		if (authSession.getAuthNote(COMPLETION) != null) {
			return collectAnswer(Status.OK, "complete", null);
		}
		String orderRef = authSession.getAuthNote(ORDER_REF);
		CollectResponse response;
		try {
			response = bankidClient.sendCollect(orderRef);
		} catch (BankidClientException e) {
			clear(authSession);
			return collectAnswer(Status.INTERNAL_SERVER_ERROR, "failed", e.getHintCode().name());
		}
		String status = response.getStatus();
		if ("pending".equals(status)) {
			return collectAnswer(Status.OK, "pending", response.getHintCode());
		}
		if ("complete".equals(status)) {
			CompletionData completion = response.getCompletionData();
			String personalNumber = completion == null || completion.getUser() == null ? null
					: completion.getUser().getPersonalNumber();
			String requested = authSession.getAuthNote(PERSONAL_NUMBER);
			if (!orderRef.equals(response.getOrderRef()) || personalNumber == null
					|| (requested != null && !requested.equals(personalNumber))) {
				logger.warnf("BankID: completed order %s does not match the order this login started", orderRef);
				clear(authSession);
				return collectAnswer(Status.INTERNAL_SERVER_ERROR, "failed", BankidHintCodes.internal.name());
			}
			try {
				authSession.setAuthNote(COMPLETION, JsonSerialization.writeValueAsString(completion));
			} catch (IOException e) {
				clear(authSession);
				return collectAnswer(Status.INTERNAL_SERVER_ERROR, "failed", BankidHintCodes.internal.name());
			}
			return collectAnswer(Status.OK, "complete", null);
		}
		clear(authSession);
		return collectAnswer(Status.INTERNAL_SERVER_ERROR, "failed", response.getHintCode());
	}

	@GET
	@Path("/done")
	public Response done(@QueryParam("state") String state) {
		AuthenticationSessionModel authSession = callback.getAndVerifyAuthenticationSession(state);
		session.getContext().setAuthenticationSession(authSession);
		String stored = authSession.getAuthNote(COMPLETION);
		boolean startedHere = startedHere(authSession);
		clear(authSession);
		if (stored == null || !startedHere) {
			return callback.error(config, "bankid.hints." + BankidHintCodes.internal.messageShortName);
		}
		CompletionData completionData;
		String username;
		try {
			completionData = JsonSerialization.readValue(stored, CompletionData.class);
			username = getUsername(completionData.getUser());
		} catch (IOException | NoSuchAlgorithmException e) {
			logger.error("BankID: cannot read the completed order", e);
			return callback.error(config, "bankid.hints." + BankidHintCodes.internal.messageShortName);
		}
		BankidUser user = completionData.getUser();

		BrokeredIdentityContext identity = new BrokeredIdentityContext(
				config.getAlias().concat("." + username), config);
		identity.setIdp(provider);
		identity.setUsername(username);
		identity.setFirstName(user.getGivenName());
		identity.setLastName(user.getSurname());

		setUserSessionNote(authSession, ".pnr", username);
		setUserSessionNote(authSession, ".issuedate", completionData.getBankIdIssueDate());
		if (completionData.getDevice() != null) {
			setUserSessionNote(authSession, ".device.ipaddress", completionData.getDevice().getIpAddress());
		}
		setUserSessionNote(authSession, ".ocspresponse", completionData.getOcspResponse());
		identity.setAuthenticationSession(authSession);

		return callback.authenticated(identity);
	}

	private void setUserSessionNote(AuthenticationSessionModel authSession, String suffix, String value) {
		if (value != null) {
			authSession.setUserSessionNote(config.getAlias().concat(suffix), value);
		}
	}

	private String getUsername(BankidUser user) throws NoSuchAlgorithmException {
		if (this.config.isSaveNinHashed()) {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(user.getPersonalNumber().getBytes(StandardCharsets.UTF_8));
			return Base64.getEncoder().encodeToString(md.digest());
		} else {
			return user.getPersonalNumber();
		}
	}

	@GET
	@Path("/cancel")
	public Response cancel(@QueryParam("state") String state) {
		AuthenticationSessionModel authSession = authSession(state);
		if (authSession == null) {
			return noSession();
		}
		cancelRunning(authSession);
		clear(authSession);
		return callback.cancelled(config);
	}

	@GET
	@Path("/error")
	public Response error(@QueryParam("code") String hintCode, @QueryParam("state") String state) {
		AuthenticationSessionModel authSession = authSession(state);
		if (authSession == null) {
			return noSession();
		}
		cancelRunning(authSession);
		clear(authSession);
		return error(BankidHintCodes.of(hintCode));
	}

	/** The current frame of the animated QR code; the page fetches one a second. */
	@GET
	@Path("/qrcode")
	public Response qrcode(@QueryParam("state") String state) {
		AuthenticationSessionModel authSession = authSession(state);
		if (authSession == null || authSession.getAuthNote(QR_START_TOKEN) == null) {
			return Response.status(Status.NOT_FOUND).build();
		}
		long elapsed = Math.max(0, Instant.now().getEpochSecond() - Long.parseLong(authSession.getAuthNote(STARTED)));
		try {
			String qrCode = qrCode(authSession.getAuthNote(QR_START_TOKEN), authSession.getAuthNote(QR_START_SECRET),
					elapsed);
			BitMatrix bitMatrix = new QRCodeWriter().encode(qrCode, BarcodeFormat.QR_CODE, QR_CODE_SIZE,
					QR_CODE_SIZE);
			ByteArrayOutputStream png = new ByteArrayOutputStream();
			MatrixToImageWriter.writeToStream(bitMatrix, "png", png);
			return Response.ok(png.toByteArray(), "image/png").cacheControl(noStore()).build();
		} catch (Exception e) {
			logger.error("BankID: cannot draw the QR code", e);
			return Response.serverError().build();
		}
	}

	public BankidIdentityProviderConfig getConfig() {
		return config;
	}

	/** The animated QR code of the BankID RP API v6.0. */
	static String qrCode(String qrStartToken, String qrStartSecret, long elapsedSeconds)
			throws InvalidKeyException, NoSuchAlgorithmException {
		String time = Long.toString(elapsedSeconds);
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(new SecretKeySpec(qrStartSecret.getBytes(StandardCharsets.US_ASCII), "HmacSHA256"));
		String qrAuthCode = String.format("%064x",
				new BigInteger(1, mac.doFinal(time.getBytes(StandardCharsets.US_ASCII))));
		return QR_CODE_PREFIX + qrStartToken + "." + time + "." + qrAuthCode;
	}

	private Response error(BankidHintCodes hint) {
		return callback.error(config, "bankid.hints." + hint.messageShortName);
	}

	/**
	 * Keycloak's callback.error and callback.cancelled need an authentication
	 * session in the context and throw a NullPointerException without one.
	 */
	private Response noSession() {
		return ErrorPage.error(session, null, Status.BAD_REQUEST, "bankid.error.session");
	}

	private LoginFormsProvider form(AuthenticationSessionModel authSession) {
		return session.getProvider(LoginFormsProvider.class).setAuthenticationSession(authSession);
	}

	/** BankID refuses a new order for a person who has one running. */
	private void cancelRunning(AuthenticationSessionModel authSession) {
		String orderRef = authSession.getAuthNote(ORDER_REF);
		if (orderRef != null && authSession.getAuthNote(COMPLETION) == null) {
			bankidClient.sendCancel(orderRef);
		}
	}

	private static void clear(AuthenticationSessionModel authSession) {
		for (String note : NOTES) {
			authSession.removeAuthNote(note);
		}
		authSession.removeAuthNote(PROVIDER);
	}

	/**
	 * Whether this provider started the session's order. Without the check, a
	 * realm's test provider, where anyone can make a BankID for any personal
	 * number, could complete an order that its production provider then accepts.
	 */
	private boolean startedHere(AuthenticationSessionModel authSession) {
		return config.getAlias().equals(authSession.getAuthNote(PROVIDER));
	}

	/**
	 * The login's authentication session, found through the browser's session
	 * cookie and the tab id inside the state. Consumes nothing.
	 */
	private AuthenticationSessionModel authSession(String state) {
		if (state == null) {
			return null;
		}
		RealmModel realm = session.getContext().getRealm();
		try {
			IdentityBrokerState parsed = IdentityBrokerState.encoded(state, realm);
			ClientModel client = parsed.getClientId() == null ? null : realm.getClientByClientId(parsed.getClientId());
			RootAuthenticationSessionModel root = new AuthenticationSessionManager(session)
					.getCurrentRootAuthenticationSession(realm);
			if (client == null || root == null || parsed.getTabId() == null) {
				return null;
			}
			AuthenticationSessionModel authSession = root.getAuthenticationSession(client, parsed.getTabId());
			if (authSession != null) {
				session.getContext().setClient(client);
				session.getContext().setAuthenticationSession(authSession);
			}
			return authSession;
		} catch (RuntimeException e) {
			logger.debugf("BankID: unusable state: %s", e.getMessage());
			return null;
		}
	}

	private static Response collectAnswer(Status httpStatus, String status, String hintCode) {
		String body = JsonSerialization.mapper.createObjectNode()
				.put("status", status)
				.put("hintCode", hintCode)
				.toString();
		return Response.status(httpStatus).entity(body).type(MediaType.APPLICATION_JSON_TYPE)
				.cacheControl(noStore()).build();
	}

	private static CacheControl noStore() {
		CacheControl cc = new CacheControl();
		cc.setNoStore(true);
		return cc;
	}
}
