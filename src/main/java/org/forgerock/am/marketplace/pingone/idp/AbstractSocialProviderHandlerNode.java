/*
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. 
 * Ping Identity Corporation only offers such software or services to legal entities who have entered into 
 * a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
 */

package org.forgerock.am.marketplace.pingone.idp;

import static java.util.Collections.singleton;
import static java.util.Collections.singletonMap;
import static org.forgerock.json.JsonPointer.ptr;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.oauth.clients.twitter.TwitterClient.OAUTH_TOKEN;
import static org.forgerock.oauth.clients.twitter.TwitterClient.OAUTH_VERIFIER;
import static org.forgerock.openam.auth.node.api.Action.goTo;
import static org.forgerock.openam.auth.node.api.Action.send;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;
import static org.forgerock.openam.integration.idm.IdmIntegrationService.DEFAULT_IDM_IDENTITY_ATTRIBUTE;
import static org.forgerock.openam.integration.idm.IdmIntegrationService.IDPS;
import static org.forgerock.openam.integration.idm.IdmIntegrationService.SELECTED_IDP;
import static org.forgerock.openam.oauth2.OAuth2Constants.Params.CODE;
import static org.forgerock.openam.oauth2.OAuth2Constants.Params.STATE;
import static org.forgerock.openam.social.idp.SocialIdPScriptContext.SOCIAL_IDP_PROFILE_TRANSFORMATION;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.security.auth.callback.Callback;

import org.forgerock.am.identity.application.LegacyIdentityService;
import org.forgerock.am.identity.persistence.IdentityStore;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth.DataStore;
import org.forgerock.oauth.OAuthClient;
import org.forgerock.oauth.OAuthException;
import org.forgerock.oauth.UserInfo;
import org.forgerock.oauth.clients.apple.AppleClient;
import org.forgerock.oauth.clients.twitter.TwitterClient;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.InputState;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.OutputState;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.nodes.helpers.IdmIntegrationHelper;
import org.forgerock.openam.auth.nodes.oauth.SharedStateAdaptor;
import org.forgerock.openam.auth.nodes.oauth.SocialOAuth2Helper;
import org.forgerock.openam.authentication.modules.common.mapping.DefaultAccountProvider;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.integration.idm.IdmIntegrationService;
import org.forgerock.openam.scripting.application.ScriptEvaluator;
import org.forgerock.openam.scripting.application.ScriptEvaluatorFactory;
import org.forgerock.openam.social.idp.OAuthClientConfig;
import org.forgerock.openam.social.idp.OpenIDConnectClientConfig;
import org.forgerock.openam.social.idp.SocialIdentityProviders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.inject.assistedinject.Assisted;
import com.iplanet.dpro.session.service.SessionService;
import com.sun.identity.authentication.service.AuthD;
import com.sun.identity.authentication.spi.RedirectCallback;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdType;
import com.sun.identity.sm.RequiredValueValidator;

/**
 * NOTE: This class was copied from here and made abstract: am-external/openam-auth-trees/auth-nodes/src/main/java/org/forgerock/openam/auth/nodes/SocialProviderHandlerNode.java
 * The only changes that have been made can be found by looking for this comment: "NOTE: changed from original".
 * This decouples the PingOne node from the auth-nodes dependency, which may change without warning.
 * When the PingOne node is moved into auth-nodes, it can be re-coupled.
 *
 * Redirects user to a social identity provider, handles post-auth, fetches and normalizes social userInfo and
 * determines whether this user has an existing AM account.
 */
// NOTE: changed from original
abstract class AbstractSocialProviderHandlerNode implements Node {
  static final String SOCIAL_OAUTH_DATA = "socialOAuthData";
  static final String ALIAS_LIST = "aliasList";
  private static final String BUNDLE = "org.forgerock.openam.auth.nodes.SocialProviderHandlerNode";
  private static final String AM_USER_ALIAS_LIST_ATTRIBUTE_NAME = "iplanet-am-user-alias-list";
  private static final String EXPECT_PROFILE_INFORMATION = "expectProfileInformation";
  private static final ObjectMapper MAPPER = new ObjectMapper();
  private static final String FORM_POST_ENTRY = "form_post_entry";

  static {
    MAPPER.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    MAPPER.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
  }

  private final Logger logger = LoggerFactory.getLogger(AbstractSocialProviderHandlerNode.class);
  private final SocialOAuth2Helper authModuleHelper;
  private final SocialIdentityProviders providerConfigStore;
  private final LegacyIdentityService identityService;
  private final Realm realm;
  private final ScriptEvaluator scriptEvaluator;
  private final Provider<SessionService> sessionServiceProvider;
  private final Config config;
  private final IdmIntegrationService idmIntegrationService;

  /**
   * Constructor.
   *
   * @param config                 node configuration instance
   * @param authModuleHelper       helper for oauth2
   * @param providerConfigStore    service containing social provider configurations
   * @param identityService        an instance of the IdentityService
   * @param realm                  the realm context
   * @param scriptEvaluatorFactory factory for ScriptEvaluators
   * @param sessionServiceProvider provider of the session service
   * @param idmIntegrationService  service that provides connectivity to IDM
   */
  @Inject
  public AbstractSocialProviderHandlerNode(@Assisted Config config,
      SocialOAuth2Helper authModuleHelper,
      SocialIdentityProviders providerConfigStore,
      LegacyIdentityService identityService,
      @Assisted Realm realm,
      ScriptEvaluatorFactory scriptEvaluatorFactory,
      Provider<SessionService> sessionServiceProvider,
      IdmIntegrationService idmIntegrationService
  ) {
    this.config = config;
    this.authModuleHelper = authModuleHelper;
    this.providerConfigStore = providerConfigStore;
    this.identityService = identityService;
    this.realm = realm;
    this.scriptEvaluator = scriptEvaluatorFactory.create(SOCIAL_IDP_PROFILE_TRANSFORMATION);
    this.sessionServiceProvider = sessionServiceProvider;
    this.idmIntegrationService = idmIntegrationService;
  }

  @Override
  public Action process(TreeContext context) throws NodeProcessException {

    if (!context.sharedState.isDefined(SELECTED_IDP)) {
      logger.error(SELECTED_IDP + " is missing in the state");
      throw new NodeProcessException(SELECTED_IDP + " not found in state");
    }
    final String selectedIdp = context.sharedState.get(SELECTED_IDP).asString();

    final OAuthClientConfig idpConfig = Optional.ofNullable(providerConfigStore.getProviders(realm)
            .get(selectedIdp))
        .orElseThrow(() -> new NodeProcessException("Selected provider does not exist."));
    final OAuthClient client = authModuleHelper.newOAuthClient(realm, idpConfig);
    final DataStore dataStore = SharedStateAdaptor.toDatastore(json(context.sharedState));

    Action action = handleCallback(context, selectedIdp, idpConfig, client, dataStore);
    if (action != null) {
      context.sharedState.remove(EXPECT_PROFILE_INFORMATION);
      return action;
    } else if (shouldExpectSocialProviderProfileInformation(context)) {
      // If this block has been entered it means the user has navigated back to the SocialProviderHandler node
      // without having performed a social authentication (back button or refreshed URL). OPENAM-20924
      context.sharedState.remove(EXPECT_PROFILE_INFORMATION);
      return goTo(SocialAuthOutcome.AUTH_INTERRUPTED.name()).build();
    }

    if (authModuleHelper.shouldPassRequestObject(idpConfig)) {
      authModuleHelper.passRequestObject(context.request.servletRequest, realm,
          (OpenIDConnectClientConfig) idpConfig, dataStore);
    }

    return send(prepareRedirectCallback(client, dataStore)).build();
  }

  private boolean shouldExpectSocialProviderProfileInformation(TreeContext context) {
    boolean expectProfileInformation;
    if (context.sharedState.isDefined(EXPECT_PROFILE_INFORMATION)) {
      expectProfileInformation = context.sharedState.get(EXPECT_PROFILE_INFORMATION).asBoolean();
    } else {
      context.sharedState.put(EXPECT_PROFILE_INFORMATION, true);
      expectProfileInformation = false;
    }
    return expectProfileInformation;
  }

  private Action handleCallback(TreeContext context, String selectedIdp, OAuthClientConfig idpConfig,
      OAuthClient client, DataStore dataStore) throws NodeProcessException {
    //Handle redirect from idp.
    return handleRedirect(context, client, idpConfig, selectedIdp, dataStore);
  }

  private Action handleRedirect(TreeContext context, OAuthClient client,
      OAuthClientConfig idpConfig, String selectedIdp,
      DataStore dataStore) throws NodeProcessException {

    if (isAllRequiredParametersPresent(client, context.request.parameters)) {

      final HashMap<String, List<String>> parameters = new HashMap<>();
      parameters.put(STATE, context.request.parameters.remove(STATE));
      parameters.put(CODE, context.request.parameters.remove(CODE));
      parameters.put(OAUTH_TOKEN, context.request.parameters.get(OAUTH_TOKEN));
      parameters.put(OAUTH_VERIFIER, context.request.parameters.get(OAUTH_VERIFIER));
      // During the web based flow Apple sends the user info as request parameter along
      // with authorization code, we read it here and set it on the parameters where
      // the commons Apple client expects to find it.
      parameters.put(AppleClient.USER, context.request.parameters.get(AppleClient.USER));

      try {
        client.handlePostAuth(dataStore, parameters).getOrThrow();

        return handleUser(context, client, idpConfig, selectedIdp, dataStore);

      } catch (OAuthException e) {
        throw new NodeProcessException(e);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new NodeProcessException(e);
      }
      catch(Exception e) {
    	  throw new NodeProcessException(e);
      }
    }
    return null;
  }

  private boolean isAllRequiredParametersPresent(OAuthClient client, Map<String, List<String>> parameters)
      throws NodeProcessException {
    if (client instanceof TwitterClient) {
      return parameters.containsKey(OAUTH_TOKEN) && parameters.containsKey(OAUTH_VERIFIER);
    } else {
      if (parameters.containsKey(CODE)) {
        if (!parameters.containsKey(STATE)) {
          throw new NodeProcessException("Not having the state could mean that this request did not come from"
              + " the IDP");
        }
        return true;
      }
    }
    return false;
  }

  private Action handleUser(TreeContext context, OAuthClient client,
      OAuthClientConfig idpConfig, String selectedIdp,
      DataStore dataStore) throws Exception {
    // Fetch the social profile from the IdP
    UserInfo profile = getUserInfo(client, dataStore);

    JsonValue objectData = normalizeClaims(idmIntegrationService.isEnabled(), selectedIdp, profile.getRawProfile());
    // Store the profile in OBJECT_ATTRIBUTES
    for (Map.Entry<String, Object> entry : objectData.asMap().entrySet()) {
      if (!entry.getKey().equals(config.usernameAttribute())) {
        idmIntegrationService.storeAttributeInState(context.transientState,
            entry.getKey(), entry.getValue());
      }
    }

    // Record the social identity subject in the profile, too
    String identity = selectedIdp + "-" + profile.getSubject();

    Optional<String> contextId = idmIntegrationService.getAttributeFromContext(context,
            config.usernameAttribute())
        .map(JsonValue::asString);

    Optional<JsonValue> user = getUser(context, identity);

    String resolvedId;
    if (contextId.isPresent()) {
      if (user.isPresent()
          && !contextId.get().equals(user.get().get(config.usernameAttribute()).asString())) {
        throw new NodeProcessException("Account does not belong to user in share state.");
      }
      resolvedId = contextId.get();
    } else {
      resolvedId = user.isPresent()
          ? user.get().get(config.usernameAttribute()).asString()
          : objectData.get(config.usernameAttribute()).asString();
      idmIntegrationService.storeAttributeInState(context.sharedState, config.usernameAttribute(),
          resolvedId);
    }

    if (resolvedId != null) {
      context.sharedState.put(USERNAME, resolvedId);
    }

    if (idmIntegrationService.isEnabled()) {
      idmIntegrationService.storeAttributeInState(context.transientState, ALIAS_LIST,
          getAliasList(context, identity, user, contextId));
    }

    Optional<String> universalId = identityService.getUniversalId(resolvedId, realm.asPath(), IdType.USER);

    if(user.isPresent()) {
      return goTo(SocialAuthOutcome.ACCOUNT_EXISTS.name())
          .withUniversalId(universalId)
          .replaceSharedState(context.sharedState.copy())
          .replaceTransientState(context.transientState.copy()
              .putPermissive(ptr(SOCIAL_OAUTH_DATA).child(selectedIdp), dataStore.retrieveData()))
          .build();
    } else {
      if(universalId.isPresent()) {
        return goTo(SocialAuthOutcome.ACCOUNT_EXISTS_NO_LINK.name())
            .withUniversalId(universalId)
            .replaceSharedState(context.sharedState.copy())
            .replaceTransientState(context.transientState.copy()
                .putPermissive(ptr(SOCIAL_OAUTH_DATA).child(selectedIdp), dataStore.retrieveData()))
            .build();
      } else {
        return goTo(SocialAuthOutcome.NO_ACCOUNT.name())
            .withUniversalId(universalId)
            .replaceSharedState(context.sharedState.copy())
            .replaceTransientState(context.transientState.copy()
                .putPermissive(ptr(SOCIAL_OAUTH_DATA).child(selectedIdp), dataStore.retrieveData()))
            .build();
      }
    }
  }

  private Optional<JsonValue> getUser(TreeContext context, String identity) throws NodeProcessException {
    if (idmIntegrationService.isEnabled()) {
      Optional<JsonValue> user = IdmIntegrationHelper.getObject(idmIntegrationService, realm,
          context.request.locales, context.identityResource, ALIAS_LIST, Optional.of(identity),
          config.usernameAttribute(), ALIAS_LIST);
      return user;
    } else {
      IdentityStore identityStore = AuthD.getAuth().getIdentityRepository(realm.asDN());
      AMIdentity amIdentity = new DefaultAccountProvider().searchUser(
          identityStore,
          singletonMap(AM_USER_ALIAS_LIST_ATTRIBUTE_NAME, singleton(identity)));

      return Optional.ofNullable(amIdentity)
          .map(id -> json(object(field(config.usernameAttribute(), id.getName()))));
    }
  }

  private UserInfo getUserInfo(OAuthClient client, DataStore dataStore) throws NodeProcessException {
    try {
      return client.getUserInfo(dataStore).getOrThrow();
    } catch (OAuthException e) {
      throw new NodeProcessException("Failed to retrieve social profile data", e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new NodeProcessException("Process interrupted", e);
    }
  }

  private JsonValue normalizeClaims(boolean isIdmEnabled, String selectedIdp, JsonValue inputClaims) {
    JsonValue returnVal = new JsonValue(new LinkedHashMap<String, Object>(1));//json(object());
    JsonValue sub = inputClaims.get("sub");

    String theSubject = "";
    if (sub.isString()) {
      theSubject = sub.asString();
    } else
      theSubject = sub.toString();

    returnVal.add("userName", theSubject);
    
    List<String> theAliasList = new ArrayList<String>();
    theAliasList.add(selectedIdp + "-" + theSubject);
    if(isIdmEnabled) {
      returnVal.add(ALIAS_LIST, theAliasList);
      returnVal.addIfNotNull("postalAddress", inputClaims.get("address").get("street_address").getObject());
      returnVal.addIfNotNull("city", inputClaims.get("address").get("locality").getObject());
      returnVal.addIfNotNull("country", inputClaims.get("address").get("country").getObject());
      returnVal.addIfNotNull("stateProvince", inputClaims.get("address").get("region").getObject());
      
    } else {
      returnVal.add(AM_USER_ALIAS_LIST_ATTRIBUTE_NAME, theAliasList);
      returnVal.addIfNotNull("street", inputClaims.get("address").get("street_address").getObject());
      returnVal.addIfNotNull("l", inputClaims.get("address").get("locality").getObject());
      returnVal.addIfNotNull("co", inputClaims.get("address").get("country").getObject());
      returnVal.addIfNotNull("st", inputClaims.get("address").get("region").getObject());
    }
    
    returnVal.addIfNotNull("mail", inputClaims.get("email").getObject());
    returnVal.addIfNotNull("telephoneNumber", inputClaims.get("phone_number").getObject());
    returnVal.addIfNotNull("givenName", inputClaims.get("given_name").getObject());
    returnVal.addIfNotNull("sn", inputClaims.get("family_name").getObject());
    returnVal.addIfNotNull("postalCode", inputClaims.get("address").get("postal_code").getObject());

    return returnVal;
  }

  private Callback prepareRedirectCallback(OAuthClient client,
      DataStore dataStore)
      throws NodeProcessException {

    RedirectCallback redirectCallback;
    try {
      URI uri = client.getAuthRedirect(dataStore, null, null).getOrThrow();
      redirectCallback = new RedirectCallback(uri.toString(), null, "GET");
      redirectCallback.setTrackingCookie(true);
    } catch (OAuthException e) {
      throw new NodeProcessException(e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new NodeProcessException(e);
    }
    return redirectCallback;
  }

  private List<String> getAliasList(TreeContext context, String identity, Optional<JsonValue> user,
      Optional<String> contextId) throws NodeProcessException {
    Set<String> aliasList = new HashSet<>();
    aliasList.add(identity);
    idmIntegrationService.getAttributeFromContext(context, ALIAS_LIST)
        .ifPresent(list -> aliasList.addAll(list.asList(String.class)));
    if (user.isPresent()) {
      aliasList.addAll(user.get().get(ALIAS_LIST).asList(String.class));
    } else if (contextId.isPresent()) {
      // try to look up user's existing aliasList if identity attribute already existed in shared state
      aliasList.addAll(IdmIntegrationHelper.getObject(idmIntegrationService, realm,
              context.request.locales, context.identityResource, config.usernameAttribute(),
              contextId, config.usernameAttribute(), ALIAS_LIST)
          .map(u -> u.get(ALIAS_LIST).asList(String.class))
          .orElse(Collections.emptyList()));
    }
    return new ArrayList<>(aliasList);
  }

  @Override
  public OutputState[] getOutputs() {
    return new OutputState[] {
        new OutputState(SOCIAL_OAUTH_DATA, json(object(
            field(SocialAuthOutcome.ACCOUNT_EXISTS.name(), true),
            field(SocialAuthOutcome.ACCOUNT_EXISTS_NO_LINK.name(), false),
            field(SocialAuthOutcome.NO_ACCOUNT.name(), false),
            field(SocialAuthOutcome.AUTH_INTERRUPTED.name(), false))).asMap(Boolean.class)),

        new OutputState(USERNAME, json(object(
            field(SocialAuthOutcome.ACCOUNT_EXISTS.name(), true),
            field(SocialAuthOutcome.ACCOUNT_EXISTS_NO_LINK.name(), false),
            field(SocialAuthOutcome.NO_ACCOUNT.name(), false),
            field(SocialAuthOutcome.AUTH_INTERRUPTED.name(), false))).asMap(Boolean.class))
    };
  }

  @Override
  public InputState[] getInputs() {
    return new InputState[]{
        new InputState(SELECTED_IDP),
        new InputState(config.usernameAttribute(), false),
        new InputState(IDPS, false)
    };
  }

  /**
   * Returns the transformation script that is applied to transform a normalized social profile to object data.
   */
  //protected abstract Script getTransformationScript();

  /**
   * The possible outcomes for the SocialProviderHandlerNode.
   */
  public enum SocialAuthOutcome {
    /**
     * Subject match found.
     */
    ACCOUNT_EXISTS,
    /**
     * Subject match found but no account link exists
     */
    ACCOUNT_EXISTS_NO_LINK,
    /**
     * Subject match not found.
     */
    NO_ACCOUNT,
    /**
     * Returned to this node without the necessary social auth parameters to continue.
     */
    AUTH_INTERRUPTED
  }

  /**
   * Configuration holder for the node.
   */
  public interface Config {
    /**
     * The attribute in which username may be found.
     *
     * @return the attribute
     */
    @Attribute(order = 300, validators = {RequiredValueValidator.class})
    default String usernameAttribute() {
      return DEFAULT_IDM_IDENTITY_ATTRIBUTE;
    }
  }
}
