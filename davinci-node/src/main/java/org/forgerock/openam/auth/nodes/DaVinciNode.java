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

import static java.util.Collections.singletonList;
import static org.forgerock.openam.auth.nodes.helpers.ScriptedNodeHelper.WILDCARD;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.sm.RequiredValueValidator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import javax.inject.Inject;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.InputState;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.OutputState;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.nodes.DaVinciClient.FlowResult;


/**
 * A node that executes "headless" DaVinci flows as described
 * <a href="https://docs.pingidentity.com/r/en-us/davinci/davinci_api_flow_launch">here</a>.
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
    configClass = DaVinciNode.Config.class)
public class DaVinciNode extends AbstractDecisionNode {

  private final Config config;
  private final DaVinciClient client;

  /**
   * Configuration for the node.
   */
  public interface Config {

    @Attribute(order = 100, validators = {RequiredValueValidator.class})
    default PingOneRegion region() {
      return PingOneRegion.NA;
    }

    @Attribute(order = 200, validators = {RequiredValueValidator.class})
    String environmentId();

    @Attribute(order = 300, validators = {RequiredValueValidator.class})
    String apiKey();

    @Attribute(order = 400, validators = {RequiredValueValidator.class})
    String flowPolicyId();

    @Attribute(order = 400)
    default List<String> inputs() {
      return singletonList(WILDCARD);
    }
  }

  @Inject
  public DaVinciNode(@Assisted Config config, DaVinciClient client) {
    this.config = config;
    this.client = client;
  }

  @Override
  public Action process(TreeContext context) throws NodeProcessException {
    // create the flow input based on the node state
    NodeState nodeState = context.getStateFor(this);
    @SuppressWarnings("unchecked")
    Entry<String, Object>[] fields = nodeState.keys().stream()
        .map(key -> field(key, nodeState.get(key)))
        .toArray(Entry[]::new);
    JsonValue flowInput = json(
        object(
            field("nodeState",
                object(fields))
        )
    );

    // execute the flow
    FlowResult result = client.executeFlowPolicy(
        config.region(),
        config.environmentId(),
        config.flowPolicyId(),
        config.apiKey(),
        flowInput
    );
    nodeState.putShared("davinciResponse", result.getResponse());
    return goTo(result.isSuccess()).build();
  }

  @Override
  public InputState[] getInputs() {
    return config.inputs().stream()
                 .map(input -> new InputState(input, true))
                 .toArray(InputState[]::new);
  }

  @Override
  public OutputState[] getOutputs() {
    return new OutputState[]{
        new OutputState("davinciResponse", Map.of("true", true, "false", false))
    };

  }
}
