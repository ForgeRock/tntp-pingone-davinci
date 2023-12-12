package org.forgerock.openam.auth.nodes;

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;

import java.net.URI;
import java.util.Objects;
import org.forgerock.http.Handler;
import org.forgerock.http.handler.HttpClientHandler;
import org.forgerock.http.header.GenericHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.Strings;

public class Foo {

  public static void main(String[] args) throws Exception {
    Request request = new Request();
    URI uri = URI.create(
        "https://orchestrate-api.pingone.com/v1/company/6baead75-aea1-4b91-b700-7bdaa75dbccd/policy/cba652c17c5ce8bd34c77f7758597003/start");
    request.setUri(uri);
    request.setMethod("POST");
    request.addHeaders(new GenericHeader("X-SK-API-KEY",
        "d53bb81b2f25cdd18e7a6468cf9574c4705cee932c965e613754a592e3c7970c6df80a0de0702115d66b7cddd2868fca893e44dad3ac48073bb56df3219ef49a4025e7758d9c58d614c7d5bee5617571779b2a0e4b5ef0d039560da1b6b7bcaa726aa870aadf0a8bfe7ffdd03073fcd85198ffd8113be7aaff9e46ff1c68c4f"));
    request.setEntity(json(
        object(
            field("nodeState", object(
                field("foo", "bar")
            ))
        )));

    Handler handler = new HttpClientHandler();
    Response response = handler.handle(new RootContext(), request).getOrThrow();
    JsonValue responseJson = new JsonValue(response.getEntity().getJson());
    if (response.getStatus().isSuccessful()) {
      // true
    } else if (Objects.equals(
        responseJson.get("capabilityName").asString(),
        "createErrorResponse"
    )) {
      System.out.println("ERROR");
    } else {
      System.out.println("Something really bad happened");
      System.out.println(response.getStatus() + "\n" + response.getHeaders().asMapOfHeaders() + "\n" + response.getEntity().getString());
    }
    System.out.println(response.getStatus());
    System.out.println(responseJson);
  }
}
