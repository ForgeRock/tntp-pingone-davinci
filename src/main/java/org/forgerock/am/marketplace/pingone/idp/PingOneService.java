package org.forgerock.am.marketplace.pingone.idp;

import static org.forgerock.json.JsonValue.json;

import javax.inject.Inject;
import javax.inject.Named;

import java.io.IOException;
import java.net.URI;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import org.forgerock.http.header.GenericHeader;
import org.forgerock.http.protocol.Form;
import org.forgerock.openam.auth.service.marketplace.TNTPPingOneConfig;
import org.forgerock.services.context.RootContext;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.http.Handler;

public class PingOneService {

    private final Handler handler;

    /**
     * Creates a new instance that will close the underlying HTTP client upon shutdown.
     */
    @Inject
    public PingOneService(@Named("CloseableHttpClientHandler") org.forgerock.http.Handler handler) {
        this.handler = handler;
    }

    public String sendPARRequest(TNTPPingOneConfig tntpPingOneConfig, String nonceParam, String stateParam,
                                 Optional<String> codeChallenge, JsonValue stateInputs,
                                 List<String> acrValues) throws PingOneServiceException {
        Request request;

        // Create the request url
        URI uri = URI.create(getPingOneBaseUrl(tntpPingOneConfig) + "/par");

        // Create the request body
        Form form = new Form();
        form.add("client_id", tntpPingOneConfig.p1APIKey());
        form.add("response_type", "code");
        form.add("redirect_uri", tntpPingOneConfig.p1RedirectURL());
        form.add("scope", "openid profile email address phone");
        form.add("nonce", nonceParam);
        form.add("state", stateParam);

        if(codeChallenge.isPresent()) {
            form.add("code_challenge", codeChallenge.get());
            form.add("code_challenge_method", "S256");
        }

        if (!acrValues.isEmpty()) {
            form.add("acr_values", String.join(" ", acrValues));
        }

        // Add any state input to the form
        for (String key : stateInputs.keys()) {
            JsonValue stateInput = stateInputs.get(key);

            String stringifiedValue;

            if(stateInput.isBoolean()) {
                stringifiedValue = stateInput.asBoolean().toString();
            } else if(stateInput.isNumber()) {
                stringifiedValue = stateInput.asNumber().toString();
            } else if(stateInput.isString()) {
                stringifiedValue = stateInput.asString();
            } else {
                stringifiedValue = stateInput.toString();
            }

            form.add(key, stringifiedValue);
        }

        try {
            request = new Request().setUri(uri).setMethod("POST");
            request.getEntity().setForm(form);
            request.addHeaders(new GenericHeader(
                    "Authorization",
                    "BASIC " + Base64.getEncoder().encodeToString((tntpPingOneConfig.p1APIKey() + ":" + tntpPingOneConfig.p1APISecret()).getBytes()))
            );
            request.getHeaders().add("Accept", "*/*");
            Response response = handler.handle(new RootContext(), request).getOrThrow();

            if (response.getStatus() == Status.CREATED || response.getStatus() == Status.OK) {
                JsonValue parResponse = json(response.getEntity().getJson());
                return parResponse.get("request_uri").asString();
            }
            else {
                throw new PingOneServiceException("PingOne API response with error."
                        + response.getStatus()
                        + "-" + response.getEntity().getString());
            }
        }
        catch (InterruptedException | IOException e) {
            throw new PingOneServiceException("Failed to process client verification" + e);
        }
    }

    private static String getPingOneBaseUrl(TNTPPingOneConfig tntpPingOneConfig) {
        return "https://auth.pingone" + tntpPingOneConfig.environmentRegion().getDomainSuffix() + "/" + tntpPingOneConfig.environmentId() + "/as";
    }
}
