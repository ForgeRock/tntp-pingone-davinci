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

import java.io.IOException;
import java.net.URI;
import java.util.Objects;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.forgerock.http.HttpApplicationException;
import org.forgerock.http.handler.HttpClientHandler;
import org.forgerock.http.header.GenericHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.thread.listener.ShutdownManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This is a simple client for executing headless DaVinci flows.
 */
@Singleton
public class DaVinciClient {

  private static final Logger logger = LoggerFactory.getLogger(DaVinciClient.class);

  private final HttpClientHandler handler;

  /**
   * Creates a new instance that will close the underlying HTTP client upon shutdown.
   */
  @Inject
  public DaVinciClient(ShutdownManager shutdownManager) throws HttpApplicationException {
    this.handler = new HttpClientHandler();
    shutdownManager.addShutdownListener(() -> {
      try {
        handler.close();
      } catch (IOException e) {
        logger.error("Could not close HTTP client", e);
      }
    });
  }

  /**
   * Executes a headless DaVinci flow policy, returning the result or throwing an exception if there is an unexpected
   * error. The input schema for the flow should match the input that is passed in here.
   */
  public FlowResult executeFlowPolicy(
      PingOneRegion region,
      String environmentId,
      String flowPolicyId,
      String apiKey,
      JsonValue flowInput) throws NodeProcessException {

    // create the request
    Request request = new Request();
    URI uri = URI.create(
        "https://orchestrate-api.pingone"
            + region.getDomainSuffix()
            + "/v1/company/"
            + environmentId
            + "/policy/"
            + flowPolicyId
            + "/start"
    );
    request.setUri(uri);
    request.setMethod("POST");
    request.addHeaders(new GenericHeader("X-SK-API-KEY", apiKey));
    request.setEntity(flowInput);

    // send the request
    try {
      logger.debug("Executing DaVinci flowPolicyId={} in environmentId={}", flowPolicyId, environmentId);
      Response response = handler.handle(new RootContext(), request).getOrThrow();
      JsonValue responseJson = new JsonValue(response.getEntity().getJson());
      boolean success;
      if (response.getStatus().isSuccessful()) {
        // this will be reached when the flow ends with a "Send Success JSON Response" node
        logger.debug("DaVinci flowPolicyId={} in environmentId={} returned a success response",
            flowPolicyId, environmentId);
        success = true;
      } else if (Objects.equals(
          responseJson.get("capabilityName").asString(),
          "createErrorResponse"
      )) {
        // this will be reached when the flow ends with a "Send Error JSON Response" node
        logger.info("DaVinci flowPolicyId={} in environmentId={} returned an error response",
            flowPolicyId, environmentId);
        success = false;
      } else {
        // if this is reached, something bad happened... likely a configuration error on the FR or DV side
        logger.error(
            "Encountered an error while executing DaVinci flowPolicyId={} in environmentId={}. "
                + "Response status={}. Response headers={}. Response body={}",
            flowPolicyId, environmentId, response.getStatus(), response.getHeaders().asMapOfHeaders(),
            response.getEntity().getString()
        );
        throw new NodeProcessException("Could not execute DaVinci flow policy");
      }
      return new FlowResult(success, responseJson);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new NodeProcessException("Interrupted while sending request", e);
    } catch (IOException e) {
      throw new NodeProcessException("Encountered exception while getting JSON response", e);
    }
  }

  /**
   * Encapsulates the result of a headless DaVinci flow execution.
   */
  public static class FlowResult {

    private final boolean success;
    private final JsonValue response;

    public FlowResult(boolean success, JsonValue response) {
      this.success = success;
      this.response = response;
    }

    /**
     * Returns whether the flow was successful. This will be true if it ends with a "Send Success JSON Response" node
     * and false if it ends with a "Send Error JSON Response" node.
     */
    public boolean isSuccess() {
      return success;
    }

    /**
     * Returns the DaVinci flow response.
     */
    public JsonValue getResponse() {
      return response;
    }
  }
}
