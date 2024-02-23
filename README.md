<!--
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
 * Copyright 2023 ForgeRock AS.
-->
# PingOne

The following document outlines how to use the PingOne Node for Identity Cloud journeys to establish a federated connection between PingOne and Identity Cloud.

This node performs an OIDC request to PingOne to delegate the user flow from Identity Cloud to PingOne using a standard OIDC redirect.  Only use this node if there is a need for PingOne to be configured as an External IdP for Identity Cloud or to execute a PingOne DaVinci flow which contains UI screens.  If that is not the case, the PingOne DaVinci API Node should be used instead.

The diagram below illustrates the integration details between PingOne Advanced Identity Cloud and the PingOne Platform.

![ScreenShot](./pingone_node_diagram.png)

This document contains sections on configuring the PingOne Node in Identity Cloud to integrate with the following specific PingOne Services:

* PingOne (External IdP)
* PingOne Verify
* PingOne Credentials
* PingID
* PingOne MFA


## Quick start with sample journeys

Identity Cloud provides sample journeys to help you understand the most common RSA SecurID use cases. To use the samples, download [the JSON files for sample journeys](https://github.com/ForgeRock/Rsa-SecurId-Auth-Tree-Nodes/tree/cloud-prep/sample) and import the downloaded sample journeys into your Identity Cloud environment.


### Dependencies

To use this node, you must have:

* a PingOne Environment
* a PingOne OIDC Application configured to your Identity Cloud instance  

## Setup

### Establishing Federation Between Identity Cloud and PingOne

#### Adding the PingOne application in the PingOne Platform

From the PingOne environment, use the Applications page to add an application to be used by Identity Cloud to connect to PingOne.

1. Go to **Applications** -> **Applications**.
2. Click the **+** icon.
3. Create the application profile by entering the following:
   * **Application name**: Identity Cloud Federation
   * **Description** (optional): Enables federation from Identity Cloud to PingOne
4. Choose the OIDC Web App for Application Type. 
5. Click Save

![ScreenShot](./pingone_setup1.png)

6. Once the Application is created, click the **Configuration** tab and then click the **Pencil** icon to edit the Application.
7. Under **PKCE Enforcement** click the drop-down and select **S256_REQUIRED**.
8. Under **Token Endpoint Authentication Method** click the drop-down and select **Client Secret Post**.
9. Next, click the **Require Pushed Authorization Request** checkbox.
10. Finally, enter the **Redirect URIs** of the ForgeRock AM instance.  
11. Click **Save** and enable the **Application** by clicking on the toggle button.

![ScreenShot](./pingone_setup2.png)

#### Configure the PingOne Node in Identity Cloud

From the Identity Cloud tenant:

1. Configure the following items in the PingOne service for Federation, refer to [PingOne Service documentation](#)

   * Region:   PingOne Region associated with your PingOne environment.
   * Environment ID: The PingOne Environment ID
   * Client ID: The Client ID of the application created in the PingOne steps above.  
   * Client Secret: The Client Secret of the application created in the PingOne steps above.
   * Redirect URI:  The Identity Cloud or Access Manager redirect URI.

2. Open the Journey or Tree where you would like to add the PingOne Node and search for the PingOne Node.  
3. Place the PingOne Node on the Journey canvas and select the node to configure the following:

   * ACR Value: The ACR value can be used to select the DaVinci flow policy to execute, if this field is not populated the Application default policy will be selected to execute.  
   * Inputs: The Inputs field is a multi-value field which is used to define the specific Node State attributes to send to PingOne.  Note, the default * will send the entire Node State of the Journey to PingOne.  

Now, the federation connection between Identity Cloud and PingOne has been completed.  The following sections will cover the integrations to the specific PingOne services.


### PingOne Federation (External IdP)

This use case would be implemented in the scenario where the customer would like to use PingOne as an External IdP for Identity Cloud.

The establishment of the federation connection between Identity Cloud and PingOne completed above covered the majority of the configuration.  The only remaining task for this use case would be to configure the following PingOne Node outcomes in the Identity Cloud Journey, see below:

### PingOne Credentials

This use case would be implemented in the scenario where the customer would like to execute the PingOne Credential flows in DaVinci from Identity Cloud, please follow the steps below to implement this use case.

1. First in PingOne DaVinci, import the PingOne Credential DaVinci flows available for [download here](#)
2. Next, create a DaVinci application as described here
3. Followed by creating a Flow Policy for the new DaVinci application as described here
4. Attached the first PingOne Credential flow to the newly created Flow Policy.  
5. Next, navigate to PingOne and select the PingOne Application created in the Federation step 1.  Click the Policies tab.
6. Next, click the Edit Policies crayon button and under the DaVinci Policies tab find and select the Flow Policy created in step 3 above.  
7. Repeat these steps for each PingOne Credentials flow.

### PingID 

This use case would be implemented in the scenario where the customer would like to execute the PingID flow in DaVinci from Identity Cloud, please follow the steps below to implement this use case.

1. First in DaVinci, import the PingID flow available for download here [TODO add link](#)

The PingID Welcome flow requires a PingOne User ID to be supplied as input to the flow.  A DaVinci Wrapper flow is available here which will retrieve the User ID from the username supplied during the federation from Identity Cloud or create a new PingOne User record if no record with the supplied username exists.

1. Import the Wrapper flow.  
2. Next, create a DaVinci application as described here
3. Followed by creating a Flow Policy for the new DaVinci application as described here
4. Attached the Wrapper flow to the newly created Flow Policy.  
5. Next, navigate to PingOne and select the PingOne Application created in the Federation step 1.  Click the Policies tab.
6. Next, click the Edit Policies crayon button and under the DaVinci Policies tab find and select the Flow Policy created in step 3 above.

Now, the PingID Welcome flow will be executed during federation from Identity Cloud.

### PingOne Authorize

TODO

# PingOne Node

The **PingOne** node enables a Trusted Federation to be established between Identity Cloud and the PingOne SSO service which can be optionally configured to trigger a PingOne DaVinci flow. 

# PingOne DaVinci API Node

The **PingOne DaVinci API** node allows a Identity Cloud journey to trigger a PingOne DaVinci flow via the API integration method where the DaVinci flow does not render any front-end UI pages.  

## Compatibility

---

You can implement this node on the following systems:

| Product | Compatible |
|---------|------------|
| ForgeRock Identity Cloud | Yes |
| ForgeRock Access Management (self-managed) | Yes |
| ForgeRock Identity Platform (self-managed) | Yes |

## Inputs
The username attribute must exist in the shared node state as an input to the node.

## Configuration

### PingOne Node 
| Property                            | Usage                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
|-------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ACR Value                           | An optional field which can be used to trigger a specific PingOne Application policy                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Inputs                              | A multi-value field which can used to select specific Node State attributes to include the Federation request to PingOne.  By default the Wildcard * value will include the entire Journey Node State in the federation request to PingOne

### PingOne DaVinci API Node
| Property                            | Usage                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
|-------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ACR Value                           | An optional field which can be used to trigger a specific PingOne Application policy                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Inputs                              | A multi-value field which can used to select specific Node State attributes to include the Federation request to PingOne.  By default the Wildcard * value will include the entire Journey Node State in the federation request to PingOne


## Outputs

---

## Outcomes

---

***Matching JSONpath Outcomes***

- Outcomes for specific JSON response data can be added. See the *JSON Response Outcome Handler* property for more details.

***Response Codes***

- Outcomes for specific response codes (for example, 401), and response code classes (for example, 2xx) can also be dynamically configured. See the *Response Code* property in the Configuration section for more details.

***Default Response***

- The request completed but no other JSONpath outcome or response code outcomes matched. Note: this outcome means a request and response were successfully processed, including responses indicating errors, for example, 4xx meaning "client error". If these should be handled then consider adding Response Code outcomes too.

***Error***

- An error occurred causing the request to fail. Check the response code, response body, or logs to see more details of the error.

Note: In cases where multiple outcomes might apply, they are triggered according to the priority order listed above. For example, a REST call might result in both a matching JSON response outcome as well as a 200 response code outcome. The matched JSON response outcome is triggered in this case.

## Troubleshooting

---

If this node logs an error, review the log messages the find the reason for the error and address the issue appropriately. There are also many publicly accessible test endpoints which can be used to help test and troubleshoot with this node. For example https://httpstat.us and https://postman-echo.com.  

## Examples

---
