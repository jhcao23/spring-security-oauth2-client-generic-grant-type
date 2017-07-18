package org.springframework.security.oauth2.client.token.grant.client;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.OAuth2AccessTokenSupport;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Iterator;
import java.util.List;

/**
 * Provider for obtaining an oauth2 access token by using client credentials.
 *
 * @author Dave Syer
 */
public class GenericClientCredentialsAccessTokenProvider extends OAuth2AccessTokenSupport implements AccessTokenProvider {

    private String paramNameClientCredentials = "client_credentials";
    private HttpMethod httpMethod = HttpMethod.POST;

    public GenericClientCredentialsAccessTokenProvider(String paramNameClientCredentials) {
        this.paramNameClientCredentials = paramNameClientCredentials;
    }
    public GenericClientCredentialsAccessTokenProvider(String paramNameClientCredentials, HttpMethod httpMethod) {
        this.paramNameClientCredentials = paramNameClientCredentials;
        this.httpMethod = httpMethod;
    }

    @Override
    protected HttpMethod getHttpMethod() {
        return httpMethod;
    }

    public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
        return resource instanceof GenericClientCredentialsResourceDetails
                && paramNameClientCredentials.equals(resource.getGrantType());
    }

    public boolean supportsRefresh(OAuth2ProtectedResourceDetails resource) {
        return false;
    }

    public OAuth2AccessToken refreshAccessToken(OAuth2ProtectedResourceDetails resource,
    		OAuth2RefreshToken refreshToken, AccessTokenRequest request) throws UserRedirectRequiredException {
        return null;
    }

    public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details, AccessTokenRequest request)
            throws UserRedirectRequiredException, AccessDeniedException, OAuth2AccessDeniedException {
        return retrieveToken(request, details, getParametersForTokenRequest(details), new HttpHeaders());
    }

    private MultiValueMap<String, String> getParametersForTokenRequest(OAuth2ProtectedResourceDetails resource) {

        MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
        form.set("grant_type", paramNameClientCredentials);

        if (resource.isScoped()) {

            StringBuilder builder = new StringBuilder();
            List<String> scope = resource.getScope();

            if (scope != null) {
                Iterator<String> scopeIt = scope.iterator();
                while (scopeIt.hasNext()) {
                    builder.append(scopeIt.next());
                    if (scopeIt.hasNext()) {
                        builder.append(' ');
                    }
                }
            }

            form.set("scope", builder.toString());
        }

        return form;

    }

}
