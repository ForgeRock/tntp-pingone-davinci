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
# PingOne Identity Provider Handler Node

A node to integrate ForgeRock's [Identity Platform][forgerock_platform] (7.4.0 and above) with PingOne DaVinci.
This node is similar to the Social Provider Handler Node, with a couple of differences.
First, rather than having to use this node after the Select Identity Provider and defining the Social Identity Provider elsewhere in AM, the connection details for the OpenID Connect PingOne application are defined in the connector itself. 
Second, the node sends an OAuth PAR request to PingOne in order to pass Tree state to PingOne that can be used within a DaVinci flow.

Copy the .jar file from the ../target directory into the ../web-container/webapps/openam/WEB-INF/lib directory where AM is deployed.  Restart the web container to pick up the new node.  The node will then appear in the authentication trees components palette.

**Overall Architecture**

![image](https://github.com/ForgeRock/tntp-pingone-davinci/assets/52761368/1d01959c-5282-4da2-bc4d-61d876133829)





**Usage**

This connector requires a PingOne environment with DaVinci in order to work. If you don't have one already, follow the instructions [here](https://docs.pingidentity.com/r/en-us/pingone/p1_start_a_pingone_trial) and create a Customer Solution environment.

The process of setting up a new environment will create a PingOne application named "Getting Started Application" that uses a DaVinci flow for authentication. This application is accessible in the PingOne console, and can easily be used with the node. The only configuration change that is necessary is setting the redirect URI to point to the ForgeRock instance (e.g., https://example.forgeblocks.com/am) and adding the OIDC scopes in the "Resources" tab ("address", "email", "phone", and "profile"). If you intend on using the ForgeRock Tree state in your DaVinci flow, you can also select "Require Pushed Authorization Request".

Once the PingOne application is set up, the required information can be copied from the PingOne console and pasted into the node configuration. Make sure to set the redirect URI to the value that was configured in the PingOne application.

TODO: Talk about ACR values, transformation script, using the Tree state in a DaVinci flow, passing back claims, etc.

**Building Authentication Nodes**

The code in this repository has binary dependencies that live in the ForgeRock maven repository. Maven can be configured to authenticate to this repository by following the following [ForgeRock Knowledge Base Article](https://backstage.forgerock.com/knowledge/kb/article/a74096897).

**SCREENSHOTS ARE GOOD LIKE BELOW**

![ScreenShot](./example.png)

        
The sample code described herein is provided on an "as is" basis, without warranty of any kind, to the fullest extent permitted by law. ForgeRock does not warrant or guarantee the individual success developers may have in implementing the sample code on their development platforms or in production configurations.

ForgeRock does not warrant, guarantee or make any representations regarding the use, results of use, accuracy, timeliness or completeness of any data or information relating to the sample code. ForgeRock disclaims all warranties, expressed or implied, and in particular, disclaims all warranties of merchantability, and warranties related to the code, or any service or software related thereto.

ForgeRock shall not be liable for any direct, indirect or consequential damages or costs of any type arising out of any action taken by you or others related to the sample code.

[forgerock_platform]: https://www.forgerock.com/platform/  
