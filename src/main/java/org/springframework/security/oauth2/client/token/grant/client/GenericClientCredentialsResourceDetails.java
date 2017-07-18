package org.springframework.security.oauth2.client.token.grant.client;

import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;

/**
 * Created by jhcao on 2017-03-27.
 */
public class GenericClientCredentialsResourceDetails extends BaseOAuth2ProtectedResourceDetails {

    public GenericClientCredentialsResourceDetails(String grantTypeName) {
        setGrantType(grantTypeName);
    }

    @Override
    public boolean isClientOnly() {
        return true;
    }

}
