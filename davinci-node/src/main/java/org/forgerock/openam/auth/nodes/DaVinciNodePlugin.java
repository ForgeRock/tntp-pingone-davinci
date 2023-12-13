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

import java.util.Collections;
import java.util.Map;
import org.forgerock.openam.auth.node.api.AbstractNodeAmPlugin;
import org.forgerock.openam.auth.node.api.Node;

public class DaVinciNodePlugin extends AbstractNodeAmPlugin {

  private static final String CURRENT_VERSION = "1.0.0";

  @Override
  protected Map<String, Iterable<? extends Class<? extends Node>>> getNodesByVersion() {
    return Collections.singletonMap(DaVinciNodePlugin.CURRENT_VERSION,
        Collections.singletonList(DaVinciNode.class));
  }

  @Override
  public String getPluginVersion() {
    return DaVinciNodePlugin.CURRENT_VERSION;
  }
}
