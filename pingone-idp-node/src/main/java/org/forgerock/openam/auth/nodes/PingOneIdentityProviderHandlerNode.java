/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2023 ForgeRock AS.
 */

package org.forgerock.openam.auth.nodes;

import static org.forgerock.http.protocol.Responses.noopExceptionAsyncFunction;
import static org.forgerock.openam.social.idp.SocialIdPScriptContext.SOCIAL_IDP_PROFILE_TRANSFORMATION;
import static org.forgerock.util.CloseSilentlyAsyncFunction.closeSilently;
import static org.forgerock.util.Closeables.closeSilentlyAsync;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.iplanet.am.util.SystemProperties;
import com.iplanet.dpro.session.service.SessionService;
import com.sun.identity.authentication.spi.RedirectCallback;
import com.sun.identity.shared.Constants;
import com.sun.identity.sm.RequiredValueValidator;
import java.net.URI;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.security.auth.callback.Callback;
import org.forgerock.am.identity.application.LegacyIdentityService;
import org.forgerock.http.Handler;
import org.forgerock.http.header.GenericHeader;
import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth.OAuthException;
import org.forgerock.oauth.clients.oauth2.PkceMethod;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.InputState;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.nodes.oauth.SocialOAuth2Helper;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.integration.idm.IdmIntegrationService;
import org.forgerock.openam.scripting.application.ScriptEvaluatorFactory;
import org.forgerock.openam.scripting.domain.EvaluatorVersion;
import org.forgerock.openam.scripting.domain.Script;
import org.forgerock.openam.scripting.domain.ScriptException;
import org.forgerock.openam.scripting.domain.ScriptingLanguage;
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
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// TODO: Display a spinner on the redirect page, if possible. Peter to ask Tyler about this.
// TODO: Update the README with information about the node.

/**
 * This node is intended to be used to provide a simple OIDC identity provider connection between ForgeRock AM and
 * PingOne. This provides a standards-based mechanism for executing DaVinci flow. The node extends {@link
 * SocialProviderHandlerNode} but has a couple of differences.
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
@Node.Metadata(outcomeProvider = SocialProviderHandlerNode.SocialAuthOutcomeProvider.class,
    configClass = PingOneIdentityProviderHandlerNode.Config.class,
    tags = {"social", "federation", "platform"})
public class PingOneIdentityProviderHandlerNode extends SocialProviderHandlerNode {

  private static final Logger logger = LoggerFactory.getLogger(PingOneIdentityProviderHandlerNode.class);

  private final Config config;
  private final Handler handler;
  private String codeChallenge;

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
  }

  @Override
  public Action process(TreeContext context) throws NodeProcessException {
    context.sharedState.put(IdmIntegrationService.SELECTED_IDP, PingOneIdentityProviders.PING_ONE_IDP_NAME);
    Action action = super.process(context);
    for (Callback callback : action.callbacks) {
      if (callback instanceof RedirectCallback) {
        RedirectCallback redirectCallback = (RedirectCallback) callback;
        String redirectUrl = redirectCallback.getRedirectUrl();

        URI uri = URI.create(redirectUrl);
        String query = uri.getQuery();
        String[] queryList = query.split("&");

        for (String queryItem : queryList) {
          String[] keyValue = queryItem.split("=");
          if(keyValue[0].equals("code_challenge")) {
            codeChallenge = keyValue[1];
          }
        }

        // send PAR request
        String parRequestUri;
        try {
          parRequestUri = sendParRequest(context).getOrThrow();
        } catch (OAuthException e) {
          logger.debug("Failed to send PAR request", e);
          throw new NodeProcessException("Failed to send PAR request", e);
        } catch (InterruptedException e) {
          logger.debug("Interrupted while sending PAR request");
          Thread.currentThread().interrupt();
          throw new NodeProcessException("Process interrupted", e);
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
    // include all inputs so that we can pass them to P1 as part of the PAR request
    return new InputState[]{
        new InputState(NodeState.STATE_FILTER_WILDCARD)
    };
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

  private Promise<String, OAuthException> sendParRequest(TreeContext context) {
    // add the basic information in the PAR request
    Form form = new Form();
    form.add("client_id", config.clientId());
    form.add("response_type", "code");
    form.add("redirect_uri", config.redirectURI());
    form.add("scope", "openid profile email address phone");
    form.add("code_challenge", codeChallenge);
    form.add("code_challenge_method", "S256");
    if (!config.acrValues().isEmpty()) {
      form.add("acr_values", String.join(" ", config.acrValues()));
    }

    // TODO: We might want to provide a way for folks to filter this down so that things like big images don't get passed.
    // This would likely be a config setting similar to the scripted decision node that we use in getInputs(...).

    // add information from the node state to the PAR request
    NodeState nodeState = context.getStateFor(this);
    for (String key : nodeState.keys()) {
      JsonValue value = nodeState.get(key);
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
    // TODO: consider additional user information and sending it to P1

    // create the PAR request and send it
    URI uri = URI.create(getPingOneBaseUrl(config) + "/par");
    Request request = new Request().setUri(uri);
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
    AP(".ap");

    private final String domainSuffix;

    PingOneRegion(String domainSuffix) {
      this.domainSuffix = domainSuffix;
    }

    public String getDomainSuffix() {
      return domainSuffix;
    }
  }

  public interface Config extends SocialProviderHandlerNode.Config {

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

    // TODO: Should this be a single value? Should we rename this to be generic, or to mention DV and Authentication policies?
    @Attribute(order = 60)
    List<String> acrValues();
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
    public PkceMethod pkceMethod() {
      return PkceMethod.S256;
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
        return Script.builder()
            .generateId()
            .setName("OIDC Profile Transformation")
            .setScript(script)
            .setLanguage(ScriptingLanguage.GROOVY)
            .setContext(SOCIAL_IDP_PROFILE_TRANSFORMATION)
            .setEvaluatorVersion(EvaluatorVersion.defaultVersion())
            .build();
      } catch (ScriptException e) {
        // this should never happen
        logger.error("Encountered unexpected error", e);
        return null;
      }
    }
  }
}
