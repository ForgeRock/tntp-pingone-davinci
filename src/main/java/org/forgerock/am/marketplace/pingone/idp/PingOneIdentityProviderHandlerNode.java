/*
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. 
 * Ping Identity Corporation only offers such software or services to legal entities who have entered into 
 * a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
 */

package org.forgerock.am.marketplace.pingone.idp;

import static java.util.Collections.singletonList;
import static org.forgerock.http.protocol.Responses.noopExceptionAsyncFunction;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.openam.auth.nodes.helpers.ScriptedNodeHelper.WILDCARD;
import static org.forgerock.openam.social.idp.SocialIdPScriptContext.SOCIAL_IDP_PROFILE_TRANSFORMATION;
import static org.forgerock.util.CloseSilentlyAsyncFunction.closeSilently;
import static org.forgerock.util.Closeables.closeSilentlyAsync;

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
import org.forgerock.openam.auth.node.api.StaticOutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.nodes.oauth.SocialOAuth2Helper;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfig;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfigChoiceValues;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.integration.idm.IdmIntegrationService;
import org.forgerock.openam.scripting.application.ScriptEvaluatorFactory;
import org.forgerock.openam.scripting.domain.EvaluatorVersion;
import org.forgerock.openam.scripting.domain.Script;
import org.forgerock.openam.scripting.domain.ScriptException;
import org.forgerock.openam.scripting.domain.ScriptingLanguage;
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
import com.iplanet.dpro.session.service.SessionService;
import com.sun.identity.authentication.spi.RedirectCallback;


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



  private final Config config;
  private TNTPPingOneConfig tntpPingOneConfig;
  private final Handler handler;


 

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
    super(config, authModuleHelper, new PingOneIdentityProviders(config, TNTPPingOneConfigChoiceValues.getTNTPPingOneConfig(config.tntpPingOneConfigName())), identityService, realm,
          scriptEvaluatorFactory, sessionServiceProvider, idmIntegrationService);

    this.config = config;
    this.handler = handler;
    this.tntpPingOneConfig = TNTPPingOneConfigChoiceValues.getTNTPPingOneConfig(config.tntpPingOneConfigName());

    // use the configured transformation script if configured, or one of the defaults otherwise
    if (idmIntegrationService.isEnabled()) {
      //transformationScript = DEFAULT_IDM_TRANSFORMATION_SCRIPT;
    } else {
      //transformationScript = DEFAULT_AM_TRANSFORMATION_SCRIPT;
    }
  }

  @Override
  public Action process(TreeContext context) {
    try {
      logger.error(loggerPrefix + "Started");
      context.getStateFor(this).putShared(IdmIntegrationService.SELECTED_IDP, PingOneIdentityProviders.PING_ONE_IDP_NAME);
      logger.error(loggerPrefix + "Calling super process");
      Action action = super.process(context);
      for (Callback callback : action.callbacks)
      {
        logger.error(loggerPrefix + "Checking if callback is redirectCallback");
        if (callback instanceof RedirectCallback)
        {
          logger.error(loggerPrefix + "Sending PAR request");
          // send PAR request
          RedirectCallback redirectCallback = (RedirectCallback) callback;
          String redirectUrl = redirectCallback.getRedirectUrl();
          String parRequestUri;
          parRequestUri = sendParRequest(context, redirectUrl).getOrThrow();

          logger.error(loggerPrefix + "Setting the PAR request URI");
          // update the RedirectCallback to include PAR URI
          String parRedirectUrl = redirectUrl + "&request_uri=" + parRequestUri;
          redirectCallback.setRedirectUrl(parRedirectUrl);
        }
      }
      logger.error(loggerPrefix + "Process end");
      return action;
    }
    catch (Exception ex) {
      String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(ex);
      logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
      context.getStateFor(this).putShared(loggerPrefix + "Exception", ex.getMessage());
      context.getStateFor(this).putShared(loggerPrefix + "StackTrace", stackTrace);
      return Action.goTo(ERROR).build();
    }
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
    return null;
  }

  private static String getPingOneBaseUrl(TNTPPingOneConfig tntpPingOneConfig) {
    return "https://auth.pingone" + tntpPingOneConfig.environmentRegion().getDomainSuffix() + "/" + tntpPingOneConfig.environmentId() + "/as";
  }

  private Promise<String, OAuthException> sendParRequest(TreeContext context, String redirectUrl) {
    // add the basic information in the PAR request
    Form form = new Form();
    form.add("client_id", tntpPingOneConfig.p1APIKey());
    form.add("response_type", "code");
    form.add("redirect_uri", tntpPingOneConfig.p1RedirectURL());
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
    URI uri = URI.create(getPingOneBaseUrl(tntpPingOneConfig) + "/par");
    Request request = null;

    try {
      request = new Request().setUri(uri);
      form.toRequestEntity(request);
      request.addHeaders(new GenericHeader(
                             "Authorization",
                             "BASIC " + Base64.getEncoder().encodeToString((tntpPingOneConfig.p1APIKey() + ":" + tntpPingOneConfig.p1APISecret()).getBytes()))
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

  public interface Config extends AbstractSocialProviderHandlerNode.Config {
    /**
     * The Configured service
     */
    @Attribute(order = 100, choiceValuesClass = TNTPPingOneConfigChoiceValues.class)
    default String tntpPingOneConfigName() {
      return TNTPPingOneConfigChoiceValues.createTNTPPingOneConfigName("Global Default");
    };

    @Attribute(order = 200)
    List<String> acrValues();

    @Attribute(order = 400)  // 300 is used by the userAttribute from the abstract class
    default List<String> inputs() {
      return singletonList(WILDCARD);
    }
  }

  private static class PingOneIdentityProviders implements SocialIdentityProviders {

    public static final String PING_ONE_IDP_NAME = PingOneIdentityProviderHandlerNode.class.getSimpleName();

    private final Map<String, OAuthClientConfig> providers;

    public PingOneIdentityProviders(Config config, TNTPPingOneConfig tntpPingOneConfig) {
      this.providers = Collections.singletonMap(
          PING_ONE_IDP_NAME,
          new PingOneOAuthClientConfig(config, tntpPingOneConfig)
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
    private final TNTPPingOneConfig tntpPingOneConfig;
    private final String baseUrl;

    public PingOneOAuthClientConfig(Config config, TNTPPingOneConfig tntpPingOneConfig) {
      this.config = config;
      this.tntpPingOneConfig = tntpPingOneConfig;
      this.baseUrl = getPingOneBaseUrl(tntpPingOneConfig);
    }

    @Override
    public String clientId() { return tntpPingOneConfig.p1APIKey(); }

    @Override
    public Optional<char[]> clientSecret() {return Optional.of(tntpPingOneConfig.p1APISecret().toCharArray()); }

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
    public String redirectURI() { return tntpPingOneConfig.p1RedirectURL(); }

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