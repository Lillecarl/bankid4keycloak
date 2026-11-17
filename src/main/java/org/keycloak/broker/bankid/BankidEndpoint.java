package org.keycloak.broker.bankid;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.IDN;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.jboss.logging.Logger;
import org.keycloak.broker.bankid.client.BankidClientException;
import org.keycloak.broker.bankid.client.SimpleBankidClient;
import org.keycloak.broker.bankid.model.AuthRequest;
import org.keycloak.broker.bankid.model.AuthResponse;
import org.keycloak.broker.bankid.model.BankidHintCodes;
import org.keycloak.broker.bankid.model.BankidUser;
import org.keycloak.broker.bankid.model.CollectResponse;
import org.keycloak.broker.bankid.model.CompletionData;
import org.keycloak.broker.bankid.model.WebRequestData;
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
import jakarta.ws.rs.core.HttpHeaders;
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
	// Set by /open: the autostart token left the server.
	private static final String SAME_DEVICE = NOTE + "sameDevice";
	// Set by a collect that carries the return URL's nonce.
	private static final String RETURNED = NOTE + "returned";
	// The alias of the provider that started the order. The other notes are
	// shared by every BankID provider of the realm.
	private static final String PROVIDER = NOTE + "provider";
	private static final String RETURN_NONCE = NOTE + "returnNonce";
	private static final String WINDOW = NOTE + "window";
	private static final String[] NOTES = { ORDER_REF, AUTO_START_TOKEN, QR_START_TOKEN, QR_START_SECRET, STARTED,
			PERSONAL_NUMBER, COMPLETION, RETURN_NONCE, WINDOW };
	// BankID's accessibility guidance: at least five minutes to scan, with a
	// countdown and a way to extend it.
	private static final long WINDOW_SECONDS = 300;

	private static final Pattern PERSONAL_NUMBER_FORMAT = Pattern.compile("(19|20)[0-9]{10}");
	private static final String QR_CODE_PREFIX = "bankid.";
	private static final Pattern REFERRING_DOMAIN = Pattern.compile("[0-9a-z.-]+");
	private static final Pattern MOBILE_USER_AGENT = Pattern.compile("Android|iPhone|iPad|iPod|Mobile");
	private static final int QR_CODE_SIZE = 246;
	private static final SecureRandom RANDOM = new SecureRandom();

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
		try {
			begin(authSession, nin, state, now());
		} catch (BankidClientException e) {
			return error(e.getHintCode());
		}
		return Response.seeOther(endpointUri("wait", state)).build();
	}

	/**
	 * Creates an order and keeps it in the session. The window is when the
	 * page's time limit started: a renewed order keeps it, a new login or an
	 * extension starts a new one.
	 */
	private void begin(AuthenticationSessionModel authSession, String nin, String state, long window) {
		String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes(32));
		AuthRequest request = new AuthRequest(session.getContext().getConnection().getRemoteAddr());
		request.setReturnUrl(endpointUri("wait", state) + "#nonce=" + nonce);
		request.setReturnRisk(true);
		request.setWeb(webRequestData());
		AuthResponse authResponse = bankidClient.sendAuth(nin, request);
		clear(authSession);
		authSession.setAuthNote(RETURN_NONCE, nonce);
		authSession.setAuthNote(ORDER_REF, authResponse.getOrderRef());
		authSession.setAuthNote(AUTO_START_TOKEN, authResponse.getAutoStartToken());
		authSession.setAuthNote(QR_START_TOKEN, authResponse.getQrStartToken());
		authSession.setAuthNote(QR_START_SECRET, authResponse.getQrStartSecret());
		authSession.setAuthNote(STARTED, Long.toString(authResponse.getAuthTimestamp()));
		authSession.setAuthNote(PROVIDER, config.getAlias());
		authSession.setAuthNote(WINDOW, Long.toString(window));
		if (nin != null) {
			authSession.setAuthNote(PERSONAL_NUMBER, nin);
		}
	}

	/** Seconds left of the page's time limit. */
	private static long remaining(AuthenticationSessionModel authSession) {
		String window = authSession.getAuthNote(WINDOW);
		return window == null ? 0 : Math.max(0, Long.parseLong(window) + WINDOW_SECONDS - now());
	}

	private static long now() {
		return Instant.now().getEpochSecond();
	}

	/**
	 * Starts a new order and a new time limit, for the page's extend button.
	 * Only while no order is under way in the app.
	 */
	@POST
	@Path("/extend")
	public Response extend(@QueryParam("state") String state) {
		AuthenticationSessionModel authSession = authSession(state);
		if (authSession == null || authSession.getAuthNote(ORDER_REF) == null
				|| authSession.getAuthNote(COMPLETION) != null) {
			return collectAnswer(Status.BAD_REQUEST, "failed", BankidHintCodes.internal.name(), 0);
		}
		cancelRunning(authSession);
		try {
			begin(authSession, authSession.getAuthNote(PERSONAL_NUMBER), state, now());
		} catch (BankidClientException e) {
			clear(authSession);
			return collectAnswer(Status.INTERNAL_SERVER_ERROR, "failed", e.getHintCode().name(), 0);
		}
		return collectAnswer(Status.OK, "pending", BankidHintCodes.outstandingTransaction.name(),
				remaining(authSession));
	}

	/**
	 * The page of a running order. /start and /login redirect here after they
	 * create the order, so a reload shows the order again instead of
	 * creating a new one.
	 */
	@GET
	@Path("/wait")
	public Response waitPage(@QueryParam("state") String state) {
		AuthenticationSessionModel authSession = authSession(state);
		if (authSession == null) {
			return noSession();
		}
		if (authSession.getAuthNote(ORDER_REF) == null) {
			return error(BankidHintCodes.internal);
		}
		return form(authSession)
				.setAttribute("state", state)
				.setAttribute("openUrl", "open?state=" + URLEncoder.encode(state, StandardCharsets.UTF_8))
				.setAttribute("showqr", config.isShowQRCode())
				.setAttribute("ninRequired", config.isRequiredNin())
				.createForm("login-bankid.ftl");
	}

	/**
	 * Same device: starts the BankID app on the current order. A mobile
	 * browser opens the app through its universal link, a desktop browser
	 * through the bankid: scheme, as BankID's autostart guide says.
	 */
	@GET
	@Path("/open")
	public Response open(@QueryParam("state") String state) {
		AuthenticationSessionModel authSession = authSession(state);
		if (authSession == null) {
			return noSession();
		}
		String token = authSession.getAuthNote(AUTO_START_TOKEN);
		if (token == null) {
			return error(BankidHintCodes.internal);
		}
		String userAgent = session.getContext().getRequestHeaders().getHeaderString(HttpHeaders.USER_AGENT);
		boolean mobile = userAgent != null && MOBILE_USER_AGENT.matcher(userAgent).find();
		String launch = (mobile ? "https://app.bankid.com/" : "bankid:///") + "?autostarttoken="
				+ URLEncoder.encode(token, StandardCharsets.UTF_8);
		authSession.setAuthNote(SAME_DEVICE, "true");
		return Response.seeOther(URI.create(launch)).cacheControl(noStore()).build();
	}

	private static byte[] randomBytes(int length) {
		byte[] bytes = new byte[length];
		RANDOM.nextBytes(bytes);
		return bytes;
	}

	/** What BankID's risk indication may know about the browser that starts the order. */
	private WebRequestData webRequestData() {
		WebRequestData web = new WebRequestData();
		String host = session.getContext().getUri().getBaseUri().getHost();
		if (host != null) {
			String domain = IDN.toASCII(host).toLowerCase(Locale.ROOT);
			if (domain.length() >= 3 && REFERRING_DOMAIN.matcher(domain).matches()) {
				web.setReferringDomain(domain);
			}
		}
		String userAgent = session.getContext().getRequestHeaders().getHeaderString(HttpHeaders.USER_AGENT);
		if (userAgent != null && !userAgent.isBlank()) {
			web.setUserAgent(userAgent.length() > 512 ? userAgent.substring(0, 512) : userAgent);
		}
		return web.getReferringDomain() == null && web.getUserAgent() == null ? null : web;
	}

	/** An absolute URL to another call of this endpoint, carrying the state. */
	private URI endpointUri(String call, String state) {
		return URI.create(session.getContext().getUri().getAbsolutePath().resolve(call) + "?state="
				+ URLEncoder.encode(state, StandardCharsets.UTF_8));
	}

	/**
	 * Polls BankID for the order and answers the page with its status. A
	 * complete order is kept only when it names the person the order asked for.
	 */
	@GET
	@Path("/collect")
	public Response collect(@QueryParam("state") String state, @QueryParam("nonce") String nonce) {
		AuthenticationSessionModel authSession = authSession(state);
		if (authSession == null || authSession.getAuthNote(ORDER_REF) == null) {
			return collectAnswer(Status.BAD_REQUEST, "failed", BankidHintCodes.internal.name());
		}
		if (!startedHere(authSession)) {
			return collectAnswer(Status.BAD_REQUEST, "failed", BankidHintCodes.internal.name());
		}
		// The page sends the nonce from the fragment of the return URL. One
		// that differs from the session's is not BankID's return for this order.
		if (nonce != null && !MessageDigest.isEqual(nonce.getBytes(StandardCharsets.US_ASCII),
				String.valueOf(authSession.getAuthNote(RETURN_NONCE)).getBytes(StandardCharsets.US_ASCII))) {
			logger.warnf("BankID: the return URL of order %s carries a wrong nonce", authSession.getAuthNote(ORDER_REF));
			cancelRunning(authSession);
			clear(authSession);
			return collectAnswer(Status.BAD_REQUEST, "failed", BankidHintCodes.internal.name());
		}
		if (nonce != null) {
			authSession.setAuthNote(RETURNED, "true");
		}
		if (authSession.getAuthNote(COMPLETION) != null) {
			return completeAnswer(authSession);
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
		String hint = response.getHintCode();
		boolean unscanned = "outstandingTransaction".equals(hint) || "noClient".equals(hint);
		if ("pending".equals(status) && unscanned && remaining(authSession) == 0) {
			cancelRunning(authSession);
			clear(authSession);
			return collectAnswer(Status.OK, "expired", hint, 0);
		}
		if ("pending".equals(status)) {
			return collectAnswer(Status.OK, "pending", hint, remaining(authSession));
		}
		if ("failed".equals(status) && "startFailed".equals(hint) && remaining(authSession) == 0) {
			clear(authSession);
			return collectAnswer(Status.OK, "expired", hint, 0);
		}
		// An order nobody started lives 30 seconds. Until the page's time
		// limit runs out, a new order replaces it, as BankID's QR guide says.
		if ("failed".equals(status) && "startFailed".equals(hint) && remaining(authSession) > 0) {
			try {
				begin(authSession, authSession.getAuthNote(PERSONAL_NUMBER), state,
						Long.parseLong(authSession.getAuthNote(WINDOW)));
			} catch (BankidClientException e) {
				clear(authSession);
				return collectAnswer(Status.INTERNAL_SERVER_ERROR, "failed", e.getHintCode().name(), 0);
			}
			return collectAnswer(Status.OK, "pending", BankidHintCodes.outstandingTransaction.name(),
					remaining(authSession));
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
			// BankID recommends cancelling an order it rates high risk.
			if ("high".equals(completion.getRisk())) {
				logger.warnf("BankID: order %s completed with high risk; refused", orderRef);
				clear(authSession);
				return collectAnswer(Status.INTERNAL_SERVER_ERROR, "failed", BankidHintCodes.internal.name());
			}
			try {
				authSession.setAuthNote(COMPLETION, JsonSerialization.writeValueAsString(completion));
			} catch (IOException e) {
				clear(authSession);
				return collectAnswer(Status.INTERNAL_SERVER_ERROR, "failed", BankidHintCodes.internal.name());
			}
			return completeAnswer(authSession);
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
		boolean returned = returned(authSession);
		clear(authSession);
		if (stored == null || !startedHere || !returned) {
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
		authSession.removeAuthNote(SAME_DEVICE);
		authSession.removeAuthNote(RETURNED);
	}

	/**
	 * Whether the browser that holds the session came back through the return
	 * URL, when the order was started on this device. /open reveals the
	 * autostart token, and the token in someone else's app completes the
	 * order; only the device that signed receives the return URL's nonce.
	 * BankID's auth reference: verify "that the device receiving the
	 * returnUrl is the same device that started the order".
	 */
	private static boolean returned(AuthenticationSessionModel authSession) {
		return authSession.getAuthNote(SAME_DEVICE) == null || authSession.getAuthNote(RETURNED) != null;
	}

	/**
	 * A complete order, or a pending one while the app has not yet returned
	 * this browser through the return URL.
	 */
	private Response completeAnswer(AuthenticationSessionModel authSession) {
		if (!returned(authSession)) {
			return collectAnswer(Status.OK, "pending", "userSign");
		}
		return collectAnswer(Status.OK, "complete", null);
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
		return collectAnswer(httpStatus, status, hintCode, 0);
	}

	private static Response collectAnswer(Status httpStatus, String status, String hintCode, long remaining) {
		String body = JsonSerialization.mapper.createObjectNode()
				.put("status", status)
				.put("hintCode", hintCode)
				.put("remaining", remaining)
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
