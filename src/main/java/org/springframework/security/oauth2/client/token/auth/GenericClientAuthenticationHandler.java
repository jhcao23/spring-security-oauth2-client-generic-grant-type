package org.springframework.security.oauth2.client.token.auth;

import org.springframework.http.HttpHeaders;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.io.UnsupportedEncodingException;

/**
 * Created by jhcao on 2017-03-27.
 */
public class GenericClientAuthenticationHandler implements ClientAuthenticationHandler {

    private String nameClientId = "client_id";			//miniprogram: appid
    private String nameClientSecret = "client_secret";	//miniprogram: secret

    public void authenticateTokenRequest(OAuth2ProtectedResourceDetails resource, MultiValueMap<String, String> form, HttpHeaders headers) {

        if (resource.isAuthenticationRequired()) {
            AuthenticationScheme scheme = AuthenticationScheme.header;
            if (resource.getClientAuthenticationScheme() != null) {
                scheme = resource.getClientAuthenticationScheme();
            }

            try {
                String clientSecret = resource.getClientSecret();
                clientSecret = clientSecret == null ? "" : clientSecret;
                switch (scheme) {
                    case header:
                        form.remove(nameClientSecret);
                        headers.add(
                                "Authorization",
                                String.format(
                                        "Basic %s",
                                        new String(Base64.encode(String.format("%s:%s", resource.getClientId(),
                                                clientSecret).getBytes("UTF-8")), "UTF-8")));
                        break;
                    case form:
                    case query:
                        form.set(nameClientId, resource.getClientId());
                        if (StringUtils.hasText(clientSecret)) {
                            form.set(nameClientSecret, clientSecret);
                        }
                        break;
                    default:
                        throw new IllegalStateException(
                                "Default authentication handler doesn't know how to handle scheme: " + scheme);
                }
            }
            catch (UnsupportedEncodingException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    public String getNameClientSecret() {
        return nameClientSecret;
    }

    public void setNameClientSecret(String nameClientSecret) {
        this.nameClientSecret = nameClientSecret;
    }

    public String getNameClientId() {
        return nameClientId;
    }

    public void setNameClientId(String nameClientId) {
        this.nameClientId = nameClientId;
    }
}
