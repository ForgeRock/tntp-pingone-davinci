/*
 * This code is to be used exclusively in connection with ForgeRock’s software or services. 
 * ForgeRock only offers ForgeRock software or services to legal entities who have entered 
 * into a binding license agreement with ForgeRock. 
 */
package org.forgerock.am.marketplace.pingone.davinci;

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;

import java.util.Map;
import java.util.Map.Entry;

import javax.inject.Inject;

import org.forgerock.am.marketplace.pingone.davinci.DaVinciClient.FlowResult;
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

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.sm.RequiredValueValidator;

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
        
    nodeState.putShared("flowOutput", result.getResponse());
    return goTo(result.isSuccess()).build();
  }

  @Override
  public InputState[] getInputs() {
    // include all inputs so that we can pass them to P1
    return new InputState[]{
        new InputState(NodeState.STATE_FILTER_WILDCARD)
    };
  }

  @Override
  public OutputState[] getOutputs() {
    return new OutputState[]{
        new OutputState("flowOutput", Map.of("true", true, "false", false))
    };
  }
}
