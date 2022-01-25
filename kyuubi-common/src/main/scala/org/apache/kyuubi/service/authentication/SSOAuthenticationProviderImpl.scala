/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.kyuubi.service.authentication

import java.util.{ArrayList, Map}
import javax.security.sasl.AuthenticationException

import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.commons.lang3.StringUtils
import org.apache.http.Consts
import org.apache.http.client.entity.UrlEncodedFormEntity
import org.apache.http.client.methods.HttpPost
import org.apache.http.impl.client.HttpClients
import org.apache.http.message.BasicNameValuePair
import org.apache.http.util.EntityUtils

import org.apache.kyuubi.Logging
import org.apache.kyuubi.config.KyuubiConf
import org.apache.kyuubi.config.KyuubiConf._

class SSOAuthenticationProviderImpl(conf: KyuubiConf) extends PasswdAuthenticationProvider
  with Logging {
  import org.apache.kyuubi.service.authentication.SSOAuthenticationProviderImpl._

  override def authenticate(user: String, password: String): Unit = {
    info(s"Start authenticating user:$user")
    if (StringUtils.isBlank(user)) {
      throw new AuthenticationException(s"Error validating SSO user, user is null" +
        s" or contains blank space")
    }
    if (StringUtils.isBlank(password)) {
      throw new AuthenticationException(s"Error validating SSO user, password is null" +
        s" or contains blank space")
    }

    val ssoURL = conf.get(AUTHENTICATION_CUSTOM_URL).get
    val clientID = conf.get(AUTHENTICATION_CUSTOM_CLIENTID).get
    val clientSecret = conf.get(AUTHENTICATION_CUSTOM_CLIENTSECRET).get
    debug(
      s"Inside SSOAuthenticationProviderImpl ssoURL: $ssoURL " +
        s"clientID: $clientID clientSecret: $clientSecret")

    val client = HttpClients.createDefault()
    val postRequest = new HttpPost(ssoURL)
    postRequest.setHeader("Content-Type", "application/x-www-form-urlencoded")
    val formParams = new ArrayList[BasicNameValuePair]()
    formParams.add(new BasicNameValuePair("grant_type", "password"))
    formParams.add(new BasicNameValuePair("scope", "openid"))
    formParams.add(new BasicNameValuePair("client_id", clientID))
    formParams.add(new BasicNameValuePair("client_secret", clientSecret))
    formParams.add(new BasicNameValuePair("username", user))
    formParams.add(new BasicNameValuePair("password", password))
    val entity = new UrlEncodedFormEntity(formParams, Consts.UTF_8)
    postRequest.setEntity(entity)

    val response = client.execute(postRequest)
    val statusCode = response.getStatusLine.getStatusCode
    debug(s"Response statusCode for user $user is:" + statusCode)

    if (statusCode >= 200 && statusCode < 300) {
      val responseEntity = response.getEntity
      val respBody = if (responseEntity != null) EntityUtils.toString(responseEntity) else null
      if (respBody == null) {
        info(s"Empty response body and authentication not successful for user: $user")
        throw new AuthenticationException(s"StatusCode 200 response body empty for user $user")
      }

      val objectMapper = new ObjectMapper
      val objectMap = objectMapper.readValue(respBody, classOf[Map[String, String]])
      val refreshToken = objectMap.get("refresh_token")
      THREAD_LOCAL_REFRESH_TOKEN.set(refreshToken)
      info(s"Authentication successful for user: $user")
    } else {
      info(s"Status code is: $statusCode and authentication not successful for user: $user")
      throw new AuthenticationException(s"Error validating user: $user")
    }
  }
}

object SSOAuthenticationProviderImpl {
  private val THREAD_LOCAL_REFRESH_TOKEN = new ThreadLocal[String]() {
    override protected def initialValue: String = null
  }
  def getRefreshToken: String = THREAD_LOCAL_REFRESH_TOKEN.get
}
