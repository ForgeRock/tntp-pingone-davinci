/*
 * This code is to be used exclusively in connection with ForgeRock’s software or services.
 * ForgeRock only offers ForgeRock software or services to legal entities who have entered
 * into a binding license agreement with ForgeRock.
 */

package org.forgerock.am.marketplace.pingone.idp;

import static java.util.Collections.singletonList;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.openam.auth.nodes.helpers.ScriptedNodeHelper.WILDCARD;
import static org.forgerock.http.protocol.Responses.noopExceptionAsyncFunction;
import static org.forgerock.openam.social.idp.SocialIdPScriptContext.SOCIAL_IDP_PROFILE_TRANSFORMATION;
import static org.forgerock.openam.social.idp.SocialIdPScriptContext.SOCIAL_IDP_PROFILE_TRANSFORMATION_NAME;
import static org.forgerock.util.CloseSilentlyAsyncFunction.closeSilently;
import static org.forgerock.util.Closeables.closeSilentlyAsync;

import java.util.Date;
import java.net.URI;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.security.auth.callback.Callback;

import org.forgerock.am.identity.application.LegacyIdentityService;
import org.forgerock.am.marketplace.pingone.PingOnePlugin;
import org.forgerock.http.Handler;
import org.forgerock.http.header.GenericHeader;
import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth.OAuthException;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.InputState;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.StaticOutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.nodes.oauth.SocialOAuth2Helper;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.integration.idm.IdmIntegrationService;
import org.forgerock.openam.scripting.application.ScriptEvaluatorFactory;
import org.forgerock.openam.scripting.domain.EvaluatorVersion;
import org.forgerock.openam.scripting.domain.Script;
import org.forgerock.openam.scripting.domain.ScriptException;
import org.forgerock.openam.scripting.domain.ScriptingLanguage;
import org.forgerock.openam.scripting.persistence.config.consumer.ScriptContext;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.openam.sm.validation.URLValidator;
import org.forgerock.openam.social.idp.ClientAuthenticationMethod;
import org.forgerock.openam.social.idp.OAuthClientConfig;
import org.forgerock.openam.social.idp.OpenIDConnectClientConfig;
import org.forgerock.openam.social.idp.RevocationOption;
import org.forgerock.openam.social.idp.SocialIdentityProviders;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.AsyncFunction;
import org.forgerock.util.Function;
import org.forgerock.util.i18n.PreferredLocales;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.iplanet.am.util.SystemProperties;
import com.iplanet.dpro.session.service.SessionService;
import com.sun.identity.authentication.spi.RedirectCallback;
import com.sun.identity.shared.Constants;
import com.sun.identity.sm.RequiredValueValidator;


/**
 * This node is intended to be used to provide a simple OIDC identity provider connection between ForgeRock AM and
 * PingOne. This provides a standards-based mechanism for executing DaVinci flow. The node extends {@link
 * AbstractSocialProviderHandlerNode} but has a couple of differences.
 * <p>
 * First, the identity provider information is configured directly in the node rather than needing to be defined
 * elsewhere in AM. This also means that the "Select Identity Provider" node doesn't need to be used before this node.
 * This is accomplished by using our own {@link SocialIdentityProviders} implementation that uses a configuration-based
 * identity provider rather than one defined in the platform.
 * <p>
 * Second, before redirecting the user agent to PingOne's authorization endpoint, the node sends a back-channel OAuth
 * PAR request that includes the node state. This provides a secure mechanism for passing context from ForgeRock to
 * PingOne that can be used in DaVinci flows.
 */
@Node.Metadata(outcomeProvider = PingOneIdentityProviderHandlerNode.OutcomeProvider.class,
    configClass = PingOneIdentityProviderHandlerNode.Config.class,
    tags = {"social", "federation", "platform"})
public class PingOneIdentityProviderHandlerNode extends AbstractSocialProviderHandlerNode {

  private static final Logger logger = LoggerFactory.getLogger(PingOneIdentityProviderHandlerNode.class);
  private String loggerPrefix = "[PingOneNode]" + PingOnePlugin.logAppender;

  private static final String BUNDLE = PingOneIdentityProviderHandlerNode.class.getName();
  private static final String ERROR = "ERROR";

  private static final Script DEFAULT_IDM_TRANSFORMATION_SCRIPT;
  private static final Script DEFAULT_AM_TRANSFORMATION_SCRIPT;

  private final Config config;
  private final Handler handler;
  private final Script transformationScript;

  static {
    try {
      // Initialize the default scripts for IDM and AM. These are exactly the same except that they use the appropriate
      // attributes defined here: https://backstage.forgerock.com/docs/idcloud/latest/identities/user-identity-properties-attributes-reference.html
      String idmScript = "import static org.forgerock.json.JsonValue.field\n"
          + "import static org.forgerock.json.JsonValue.json\n"
          + "import static org.forgerock.json.JsonValue.object\n"
          + "\n"
          + "import org.forgerock.json.JsonValue\n"
          + "\n"
          + "JsonValue managedUser = json(object(\n"
          + "        field(\"userName\", normalizedProfile.username),\n"
          + "        field(\"aliasList\", selectedIdp + '-' + normalizedProfile.id.asString())))\n"
          + "\n"
          + "if (normalizedProfile.email.isNotNull()) managedUser.put(\"mail\", normalizedProfile.email)\n"
          + "if (normalizedProfile.phone.isNotNull()) managedUser.put(\"telephoneNumber\", normalizedProfile.phone)\n"
          + "if (normalizedProfile.givenName.isNotNull()) managedUser.put(\"givenName\", normalizedProfile.givenName)\n"
          + "if (normalizedProfile.familyName.isNotNull()) managedUser.put(\"sn\", normalizedProfile.familyName)\n"
          + "if (normalizedProfile.photoUrl.isNotNull()) managedUser.put(\"profileImage\", normalizedProfile.photoUrl)\n"
          + "if (normalizedProfile.postalAddress.isNotNull()) managedUser.put(\"postalAddress\", normalizedProfile.postalAddress)\n"
          + "if (normalizedProfile.addressLocality.isNotNull()) managedUser.put(\"city\", normalizedProfile.addressLocality)\n"
          + "if (normalizedProfile.addressRegion.isNotNull()) managedUser.put(\"stateProvince\", normalizedProfile.addressRegion)\n"
          + "if (normalizedProfile.postalCode.isNotNull()) managedUser.put(\"postalCode\", normalizedProfile.postalCode)\n"
          + "if (normalizedProfile.country.isNotNull()) managedUser.put(\"country\", normalizedProfile.country)\n"
          + "\n"
          + "return managedUser";
      DEFAULT_IDM_TRANSFORMATION_SCRIPT = Script.builder()
          .generateId()
          .setName("Default IDM Transformation Script")
          .setScript(idmScript)
          .setLanguage(ScriptingLanguage.GROOVY)
          .setContext(SOCIAL_IDP_PROFILE_TRANSFORMATION)
          .setEvaluatorVersion(EvaluatorVersion.defaultVersion())
          .build();

      String amScript = "import static org.forgerock.json.JsonValue.field\n"
          + "import static org.forgerock.json.JsonValue.json\n"
          + "import static org.forgerock.json.JsonValue.object\n"
          + "\n"
          + "import org.forgerock.json.JsonValue\n"
          + "\n"
          + "JsonValue identity = json(object(\n"
          + "        field(\"userName\", normalizedProfile.username),\n"
          + "        field(\"iplanet-am-user-alias-list\", selectedIdp + '-' + normalizedProfile.id.asString())))\n"
          + "\n"
          + "if (normalizedProfile.email.isNotNull()) identity.put(\"mail\", normalizedProfile.email)\n"
          + "if (normalizedProfile.phone.isNotNull()) identity.put(\"telephoneNumber\", normalizedProfile.phone)\n"
          + "if (normalizedProfile.givenName.isNotNull()) identity.put(\"givenName\", normalizedProfile.givenName)\n"
          + "if (normalizedProfile.familyName.isNotNull()) identity.put(\"sn\", normalizedProfile.familyName)\n"
          + "if (normalizedProfile.photoUrl.isNotNull()) identity.put(\"labeledURI\", normalizedProfile.photoUrl)\n"
          + "if (normalizedProfile.postalAddress.isNotNull()) identity.put(\"street\", normalizedProfile.postalAddress)\n"
          + "if (normalizedProfile.addressLocality.isNotNull()) identity.put(\"l\", normalizedProfile.addressLocality)\n"
          + "if (normalizedProfile.addressRegion.isNotNull()) identity.put(\"st\", normalizedProfile.addressRegion)\n"
          + "if (normalizedProfile.postalCode.isNotNull()) identity.put(\"postalCode\", normalizedProfile.postalCode)\n"
          + "if (normalizedProfile.country.isNotNull()) identity.put(\"co\", normalizedProfile.country)\n"
          + "\n"
          + "return identity";
      DEFAULT_AM_TRANSFORMATION_SCRIPT = Script.builder()
          .generateId()
          .setName("Default AM Transformation Script")
          .setScript(amScript)
          .setLanguage(ScriptingLanguage.GROOVY)
          .setContext(SOCIAL_IDP_PROFILE_TRANSFORMATION)
          .setEvaluatorVersion(EvaluatorVersion.defaultVersion())
          .build();
    } catch (ScriptException e) {
      // this should never happen
      throw new RuntimeException("Encountered unexpected error", e);
    }
  }

  /**
   * Constructor.
   *
   * @param config                 node configuration instance
   * @param authModuleHelper       helper for oauth2
   * @param identityService        an instance of the IdentityService
   * @param realm                  the realm context
   * @param scriptEvaluatorFactory factory for ScriptEvaluators
   * @param sessionServiceProvider provider of the session service
   * @param idmIntegrationService  service that provides connectivity to IDM
   * @param handler                HTTP handler for sending PAR requests
   */
  @Inject
  public PingOneIdentityProviderHandlerNode(@Assisted Config config,
      SocialOAuth2Helper authModuleHelper,
      LegacyIdentityService identityService,
      @Assisted Realm realm,
      ScriptEvaluatorFactory scriptEvaluatorFactory,
      Provider<SessionService> sessionServiceProvider,
      IdmIntegrationService idmIntegrationService,
      @Named("CloseableHttpClientHandler") Handler handler) {
    super(config, authModuleHelper, new PingOneIdentityProviders(config), identityService, realm,
        scriptEvaluatorFactory, sessionServiceProvider, idmIntegrationService);
    this.config = config;
    this.handler = handler;

    // use the configured transformation script if configured, or one of the defaults otherwise
    if (idmIntegrationService.isEnabled()) {
      transformationScript = DEFAULT_IDM_TRANSFORMATION_SCRIPT;
    } else {
      transformationScript = DEFAULT_AM_TRANSFORMATION_SCRIPT;
    }
  }

  @Override
  public Action process(TreeContext context) throws NodeProcessException {
	context.getStateFor(this).putShared(IdmIntegrationService.SELECTED_IDP, PingOneIdentityProviders.PING_ONE_IDP_NAME);
    Action action = super.process(context);
    for (Callback callback : action.callbacks) {
      if (callback instanceof RedirectCallback) {
        // send PAR request
        RedirectCallback redirectCallback = (RedirectCallback) callback;
        String redirectUrl = redirectCallback.getRedirectUrl();
        String parRequestUri;
        try {
          parRequestUri = sendParRequest(context, redirectUrl).getOrThrow();
        } catch (OAuthException ex) {
          logger.debug("Failed to send PAR request", ex);
          String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(ex);
          logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
          context.getStateFor(this).putTransient(loggerPrefix + "Exception", new Date() + ": " + ex.getMessage());
          context.getStateFor(this).putTransient(loggerPrefix + "StackTrace", new Date() + ": " + stackTrace);
          return Action.goTo(ERROR).withHeader("Error occurred").withErrorMessage(ex.getMessage()).build();
        } catch (InterruptedException ex) {
          logger.debug("Interrupted while sending PAR request");
          Thread.currentThread().interrupt();
          String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(ex);
          logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
          context.getStateFor(this).putTransient(loggerPrefix + "Exception", new Date() + ": " + ex.getMessage());
          context.getStateFor(this).putTransient(loggerPrefix + "StackTrace", new Date() + ": " + stackTrace);
          return Action.goTo(ERROR).withHeader("Error occurred").withErrorMessage(ex.getMessage()).build();
        }
        // update the RedirectCallback to include PAR URI
        String parRedirectUrl = redirectUrl + "&request_uri=" + parRequestUri;
        redirectCallback.setRedirectUrl(parRedirectUrl);
      }
    }
    return action;
  }

  @Override
  public InputState[] getInputs() {
    return config.inputs().stream()
                 .map(input -> new InputState(input, true))
                 .toArray(InputState[]::new);
  }

  /**
   * Return only those state values declared as inputs.
   *
   * @param state Either shared or transient state
   * @return Filtered state
   */
  private JsonValue filterInputs(JsonValue state) {
    if (config.inputs().contains(WILDCARD)) {
      return state.copy();
    } else {
      JsonValue filtered = json(object());
      config.inputs().forEach(input -> {
        if (state.isDefined(input)) {
          filtered.put(input, state.get(input));
        }
      });
      return filtered;
    }
  }

  @Override
  protected Script getTransformationScript() {
    return transformationScript;
  }

  // TODO: This was copied from AbstractSocialAuthLoginNode.getServerURL.
  // Use it from there when moved into openam-auth-trees/auth-nodes.
  private static String getServerURL() {
    final String protocol = SystemProperties.get(Constants.AM_SERVER_PROTOCOL);
    final String host = SystemProperties.get(Constants.AM_SERVER_HOST);
    final String port = SystemProperties.get(Constants.AM_SERVER_PORT);
    final String descriptor = SystemProperties.get(Constants.AM_SERVICES_DEPLOYMENT_DESCRIPTOR);

    if (protocol != null && host != null && port != null && descriptor != null) {
      return protocol + "://" + host + ":" + port + descriptor;
    } else {
      return "";
    }
  }

  private static String getPingOneBaseUrl(Config config) {
    return "https://auth.pingone" + config.region().getDomainSuffix() + "/" + config.environmentId() + "/as";
  }

  private Promise<String, OAuthException> sendParRequest(TreeContext context, String redirectUrl) {
    // add the basic information in the PAR request
    Form form = new Form();
    form.add("client_id", config.clientId());
    form.add("response_type", "code");
    form.add("redirect_uri", config.redirectURI());
    form.add("scope", "openid profile email address phone");
    if (!config.acrValues().isEmpty()) {
      form.add("acr_values", String.join(" ", config.acrValues()));
    }

    // add the PKCE parameters from the redirect URL
    URI redirectUri = URI.create(redirectUrl);
    String query = redirectUri.getQuery();
    String[] queryList = query.split("&");

    for (String queryItem : queryList) {
      String[] keyValue = queryItem.split("=");
      if (keyValue[0].equals("code_challenge")) {
        form.add("code_challenge", keyValue[1]);
        form.add("code_challenge_method", "S256");
      }
    }

    // add information from the node state to the PAR request
    JsonValue filteredShared = filterInputs(context.sharedState);
    JsonValue filteredTransient = filterInputs(context.transientState);

    // filter shared state
    for (String key : filteredShared.keys()) {
      JsonValue value = filteredShared.get(key);
      String stringifiedValue;
      if (value.isBoolean()) {
        stringifiedValue = value.asBoolean().toString();
      } else if (value.isNumber()) {
        stringifiedValue = value.asNumber().toString();
      } else if (value.isString()) {
        stringifiedValue = value.asString();
      } else {
        stringifiedValue = value.toString();
      }
      form.add(key, stringifiedValue);
    }

    // filter transient state
    for (String key : filteredTransient.keys()) {
      JsonValue value = filteredTransient.get(key);
      String stringifiedValue;
      if (value.isBoolean()) {
        stringifiedValue = value.asBoolean().toString();
      } else if (value.isNumber()) {
        stringifiedValue = value.asNumber().toString();
      } else if (value.isString()) {
        stringifiedValue = value.asString();
      } else {
        stringifiedValue = value.toString();
      }
      form.add(key, stringifiedValue);
    }

    // create the PAR request and send it
    URI uri = URI.create(getPingOneBaseUrl(config) + "/par");
    Request request = null;

    try {
    	request = new Request().setUri(uri);
        form.toRequestEntity(request);
        request.addHeaders(new GenericHeader(
            "Authorization",
            "BASIC " + Base64.getEncoder().encodeToString((config.clientId() + ":" + config.clientSecret()).getBytes()))
        );
        return handler.handle(new RootContext(), request)
            .thenAlways(closeSilentlyAsync(request))
            .thenAsync(closeSilently(handleParResponse()), noopExceptionAsyncFunction())
            .then(mapToParRequestUri());
    }
    catch (Exception ex) {
    	//never gets here
    }
    finally {
    	if (request!=null)
    		request.close();
    }
    return null;
  }

  private AsyncFunction<Response, JsonValue, OAuthException> handleParResponse() {
    return response -> {
      if (!response.getStatus().isSuccessful()) {
        throw new OAuthException("Unable to process request: " + response.getEntity(), response.getCause());
      }

      return response.getEntity().getJsonAsync().then(JsonValue::json, e -> {
        throw new OAuthException("Unable to process request: " + response.getEntity(), e);
      });
    };
  }

  private Function<JsonValue, String, OAuthException> mapToParRequestUri() {
    return (responseJson) -> {
      String requestUri = responseJson.get("request_uri").asString();
      if (requestUri == null) {
        throw new OAuthException("Unable to retrieve request_uri from PAR response: " + responseJson);
      }
      return requestUri;
    };
  }

  public enum PingOneRegion {
    NA(".com"),
    CA(".ca"),
    EU(".eu"),
    ASIA(".asia");

    private final String domainSuffix;

    PingOneRegion(String domainSuffix) {
      this.domainSuffix = domainSuffix;
    }

    public String getDomainSuffix() {
      return domainSuffix;
    }
  }

  public interface Config extends AbstractSocialProviderHandlerNode.Config {

    @Attribute(order = 10, validators = {RequiredValueValidator.class})
    default PingOneRegion region() {
      return PingOneRegion.NA;
    }

    @Attribute(order = 20, validators = {RequiredValueValidator.class})
    String environmentId();

    @Attribute(order = 30, validators = {RequiredValueValidator.class})
    String clientId();

    @Attribute(order = 40, validators = {RequiredValueValidator.class})
    @Password
    String clientSecret();

    @Attribute(order = 50, validators = {RequiredValueValidator.class, URLValidator.class})
    default String redirectURI() {
      return getServerURL();
    }

    @Attribute(order = 60)
    List<String> acrValues();

    @Attribute(order = 70)
    default List<String> inputs() {
      return singletonList(WILDCARD);
    }

  }

  private static class PingOneIdentityProviders implements SocialIdentityProviders {

    public static final String PING_ONE_IDP_NAME = PingOneIdentityProviderHandlerNode.class.getSimpleName();

    private final Map<String, OAuthClientConfig> providers;

    public PingOneIdentityProviders(Config config) {
      this.providers = Collections.singletonMap(
          PING_ONE_IDP_NAME,
          new PingOneOAuthClientConfig(config)
      );
    }


    @Override
    public Map<String, OAuthClientConfig> getProviders(Realm realm) {
      return providers;
    }

    @Override
    public Map<String, OAuthClientConfig> load(Realm realm) {
      return providers;
    }
  }

  private static class PingOneOAuthClientConfig implements OpenIDConnectClientConfig {

    private static final Script OIDC_TRANSFORMATION_SCRIPT;

    static {
      // TODO: Things blow up when using the "Normalized Profile to Identity" script followed by the "Provision Dynamic Account" node.
      // This is due to a bug in the node where null attribute values result in a NPE. Specifically this... field("cn", normalizedProfile.displayName),
      // We can fix the node itself, but could also look into providing a better script that doesn't allow null values.
      // The "Normalized Profile to Managed User" script is better about this, but doesn't include an account link mapping... which always results in "no account exists" and duplicate users.

      // This maps all the standard OIDC claims defined in P1 except for the following: name, middle_name, nickname, zoneinfo, and updated_at.
      // These don't have direct mappings to FR. Some of these aren't required, but have been seen in scripts like normalized-profile-to-managed-user.js.
      String script = "import static org.forgerock.json.JsonValue.field\n"
          + "import static org.forgerock.json.JsonValue.json\n"
          + "import static org.forgerock.json.JsonValue.object\n"
          + "\n"
          + "return json(object(\n"
          + "        field(\"id\", rawProfile.sub),\n"
          + "        field(\"username\", rawProfile.preferred_username),\n"
          + "        field(\"email\", rawProfile.email),\n"
          + "        field(\"phone\", rawProfile.phone_number),\n"
          + "        field(\"givenName\", rawProfile.given_name),\n"
          + "        field(\"familyName\", rawProfile.family_name),\n"
          + "        field(\"locale\", rawProfile.locale),\n"
          + "        field(\"photoUrl\", rawProfile.picture),\n"
          + "        field(\"postalAddress\", rawProfile.address.street_address),\n"
          + "        field(\"addressLocality\", rawProfile.address.locality),\n"
          + "        field(\"addressRegion\", rawProfile.address.region),\n"
          + "        field(\"postalCode\", rawProfile.address.postal_code),\n"
          + "        field(\"country\", rawProfile.address.country)))";
      try {
        OIDC_TRANSFORMATION_SCRIPT = Script.builder()
            .generateId()
            .setName("OIDC Profile Transformation")
            .setScript(script)
            .setLanguage(ScriptingLanguage.GROOVY)
            .setContext(SOCIAL_IDP_PROFILE_TRANSFORMATION)
            .setEvaluatorVersion(EvaluatorVersion.defaultVersion())
            .build();
      } catch (ScriptException e) {
        // this should never happen
        throw new RuntimeException("Encountered unexpected error", e);
      }
    }

    private final Config config;
    private final String baseUrl;

    public PingOneOAuthClientConfig(Config config) {
      this.config = config;
      this.baseUrl = getPingOneBaseUrl(config);
    }

    @Override
    public String clientId() {
      return config.clientId();
    }

    @Override
    public Optional<char[]> clientSecret() {
      return Optional.of(config.clientSecret().toCharArray());
    }

    @Override
    public String authorizationEndpoint() {
      return baseUrl + "/authorize";
    }

    @Override
    public String tokenEndpoint() {
      return baseUrl + "/token";
    }

    @Override
    public String userInfoEndpoint() {
      return null;
    }

    @Override
    public String introspectEndpoint() {
      return null;
    }

    @Override
    public String redirectURI() {
      return config.redirectURI();
    }

    @Override
    public String redirectAfterFormPostURI() {
      return null;
    }

    @Override
    public List<String> scopes() {
      // we're just requesting all OIDC scopes, but this could be configurable
      return ImmutableList.of("openid", "profile", "email", "address", "phone");
    }

    @Override
    public ClientAuthenticationMethod clientAuthenticationMethod() {
      return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
    }

    @Override
    public List<String> acrValues() {
      return config.acrValues();
    }

    @Override
    public String wellKnownEndpoint() {
      return baseUrl + "/.well-known/openid-configuration";
    }

    @Override
    public String requestObjectAudience() {
      return null;
    }

    @Override
    public Boolean encryptedIdTokens() {
      return false;
    }

    @Override
    public String issuer() {
      return baseUrl;
    }

    @Override
    public String claims() {
      return null;
    }

    @Override
    public String jwksUriEndpoint() {
      return baseUrl + "/jwks";
    }

    @Override
    public String jwtEncryptionAlgorithm() {
      return "NONE";
    }

    @Override
    public String jwtEncryptionMethod() {
      return "NONE";
    }

    @Override
    public Set<RevocationOption> revocationCheckOptions() {
      return Collections.singleton(RevocationOption.DISABLE_REVOCATION_CHECKING);
    }

    @Override
    public String provider() {
      return PingOneIdentityProviders.PING_ONE_IDP_NAME;
    }

    @Override
    public String authenticationIdKey() {
      return "sub";
    }

    @Override
    public Map<String, String> uiConfig() {
      return null;
    }

    @Override
    public Script transform() {
      return OIDC_TRANSFORMATION_SCRIPT;
    }
  }

  public static class OutcomeProvider implements StaticOutcomeProvider
  {
    @Override
    public List<Outcome> getOutcomes(PreferredLocales locales) {
      ResourceBundle bundle = locales.getBundleInPreferredLocale(PingOneIdentityProviderHandlerNode.BUNDLE,
                                                                 OutcomeProvider.class.getClassLoader());

      return ImmutableList.of(
              new Outcome(SocialAuthOutcome.ACCOUNT_EXISTS.name(),
                          bundle.getString("accountExistsOutcome")),
              new Outcome(SocialAuthOutcome.ACCOUNT_EXISTS_NO_LINK.name(),
                          bundle.getString("accountExistsNoLinkOutcome")),
              new Outcome(SocialAuthOutcome.NO_ACCOUNT.name(),
                          bundle.getString("noAccountOutcome")),
              new Outcome(ERROR, bundle.getString("errorOutcome")));
    }
  }
}
