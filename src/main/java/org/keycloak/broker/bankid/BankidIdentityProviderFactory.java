package org.keycloak.broker.bankid;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import org.apache.http.client.HttpClient;
import org.keycloak.broker.bankid.client.SimpleBankidClient;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.connections.httpclient.HttpClientBuilder;
import org.keycloak.connections.httpclient.ProxyMappings;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

public class BankidIdentityProviderFactory extends AbstractIdentityProviderFactory	<BankidIdentityProvider> {

	public static final String PROVIDER_ID = "bankid";

	/** A client and the configuration it was built from. */
	private record Loaded(String version, SimpleBankidClient client) {
	}

	/** One pooled client per identity provider, rebuilt when its configuration or key stores change. */
	private static final Map<String, Loaded> CLIENTS = new ConcurrentHashMap<>();

	@Override
	public String getName() {
		return "BankID e-legitimation";
	}

	@Override
	public BankidIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
		BankidIdentityProviderConfig config = new BankidIdentityProviderConfig(model);
		// The internal id is unique across realms; an alias is unique only inside one.
		String id = model.getInternalId() != null ? model.getInternalId() : String.valueOf(config.getAlias());
		String version = version(config);
		Loaded loaded = CLIENTS.compute(id, (key, current) -> {
			if (current != null && current.version().equals(version)) {
				return current;
			}
			Loaded fresh = new Loaded(version,
					new SimpleBankidClient(buildBankidHttpClient(config), config.getApiUrl()));
			if (current != null) {
				current.client().close();
			}
			return fresh;
		});
		return new BankidIdentityProvider(session, config, loaded.client());
	}

	/**
	 * Names everything the client is built from: the provider configuration,
	 * and the modification times of the key store files, so that a renewed
	 * certificate at the same path takes effect without a restart.
	 */
	private static String version(BankidIdentityProviderConfig config) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			for (Map.Entry<String, String> entry : new TreeMap<>(config.getConfig()).entrySet()) {
				digest.update((entry.getKey() + "=" + entry.getValue() + "\n").getBytes(StandardCharsets.UTF_8));
			}
			for (String property : new String[] { BankidIdentityProviderConfig.BANKID_KEYSTORE_FILE_PROPERTY_NAME,
					BankidIdentityProviderConfig.BANKID_TRUSTSTORE_FILE_PROPERTY_NAME }) {
				String file = config.getConfig().get(property);
				String modified = file == null ? "" : Files.getLastModifiedTime(Path.of(file)).toString();
				digest.update((property + "@" + modified + "\n").getBytes(StandardCharsets.UTF_8));
			}
			return HexFormat.of().formatHex(digest.digest());
		} catch (IOException e) {
			throw new IllegalStateException("BankID: cannot read the key store files", e);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	@Override
	public BankidIdentityProviderConfig createConfig() {
		return new BankidIdentityProviderConfig();
	}

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
				.property().name(BankidIdentityProviderConfig.BANKID_APIURL_PROPERTY_NAME).label("BankID API base URL").helpText("The base URL for the BankID API. Without the trailing slash. Normally https://appapi2.bankid.com")
                .type(ProviderConfigProperty.STRING_TYPE).add()

				.property().name(BankidIdentityProviderConfig.BANKID_KEYSTORE_FILE_PROPERTY_NAME).label("Keystore file").helpText("Full path to the keystore file, that holds the client certificate, including filename i.e. /path/to/file/myfile.p12")
                .type(ProviderConfigProperty.STRING_TYPE).add()
				
				.property().name(BankidIdentityProviderConfig.BANKID_KEYSTORE_PASSWORD_PROPERTY_NAME).label("Keystore password").helpText("The password for the keystore.")
                .type(ProviderConfigProperty.PASSWORD).add()
				
				.property().name(BankidIdentityProviderConfig.BANKID_PRIVATEKEY_PASSWORD_PROPERTY_NAME).label("Password for the private key").helpText("Password for the private key.")
                .type(ProviderConfigProperty.PASSWORD).add()
				
				.property().name(BankidIdentityProviderConfig.BANKID_TRUSTSTORE_FILE_PROPERTY_NAME).label("Truststore file").helpText("Full path to the truststore file, that holds the CA for the server certificate, including filename i.e. /path/to/file/bankid-truststore.p12")
                .type(ProviderConfigProperty.STRING_TYPE).add()
				
				.property().name(BankidIdentityProviderConfig.BANKID_TRUSTSTORE_PASSWORD_PROPERTY_NAME).label("Truststore password").helpText("The password for the truststore.")
                .type(ProviderConfigProperty.PASSWORD).add()
				
				.property().name(BankidIdentityProviderConfig.BANKID_REQUIRE_NIN).label("Require Personal Number").helpText("Require the user to provide their Personal Number before logging in.")
                .defaultValue(false)
				.type(ProviderConfigProperty.BOOLEAN_TYPE).add()

				.property().name(BankidIdentityProviderConfig.BANKID_SHOW_QR_CODE).label("Show QR code").helpText("Show QR code to allow user to use when starting the authentication.")
				.defaultValue(true)
                .type(ProviderConfigProperty.BOOLEAN_TYPE).add()

				.property().name(BankidIdentityProviderConfig.BANKID_SAVE_NIN_HASH).label("Use hashed Personal Number").helpText("Used hashed (SHA-256) Personal Number in keycloak instead of storing it in clear text.")
				.defaultValue(false)
				.type(ProviderConfigProperty.BOOLEAN_TYPE).add()

		.property().name(BankidIdentityProviderConfig.BANKID_CONNECTION_POOL_SIZE).label("Connection pool size").helpText("Total HTTP connections available for BankID calls.")
		.defaultValue("200")
		.type(ProviderConfigProperty.STRING_TYPE).add()

		.property().name(BankidIdentityProviderConfig.BANKID_MAX_POOLED_PER_ROUTE).label("Connections per host").helpText("Maximum concurrent connections to a single BankID endpoint.")
		.defaultValue("50")
		.type(ProviderConfigProperty.STRING_TYPE).add()

			.build();
	}

	private HttpClient buildBankidHttpClient(BankidIdentityProviderConfig config) {
		try {
			return (new HttpClientBuilder()).keyStore(config.getKeyStore(), config.getPrivateKeyPassword())
					.trustStore(config.getTrustStore())
					// HttpClientBuilder waits forever by default; a stalled BankID
					// call would hold a Keycloak worker thread with it.
					.establishConnectionTimeout(5, TimeUnit.SECONDS)
					.socketTimeout(10, TimeUnit.SECONDS)
					.disableCookies(true)
					.proxyMappings(generateProxyMapping())
					.connectionPoolSize(config.getConnectionPoolSize())
					.maxPooledPerRoute(config.getConnectionPoolPerRoute())
					.build();
		} catch (Exception e) {
			throw new RuntimeException("Failed to create BankID HTTP Client", e);
		}
	}

	private ProxyMappings generateProxyMapping() {
		String httpsProxy = System.getenv("HTTPS_PROXY");
		if (httpsProxy == null) {
			httpsProxy = System.getenv("https_proxy");
		}

		String noProxy = System.getenv("NO_PROXY");
		if (noProxy == null) {
			noProxy = System.getenv("no_proxy");
		}

		return ProxyMappings.withFixedProxyMapping(httpsProxy, noProxy);
	}

}
