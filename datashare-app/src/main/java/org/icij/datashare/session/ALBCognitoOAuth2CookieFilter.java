package org.icij.datashare.session;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import net.codestory.http.Context;
import net.codestory.http.payload.Payload;
import net.codestory.http.security.SessionIdStore;
import org.icij.datashare.PropertiesProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.concurrent.ExecutionException;

import static java.util.Optional.ofNullable;
import static org.icij.datashare.user.User.fromJson;

@Singleton
public class ALBCognitoOAuth2CookieFilter extends OAuth2CookieFilter {
    private final DefaultApi20 defaultOauthApi;
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final String oauthApiUrl;
    private final String oauthAuthorizeUrl;
    private final String oauthCallbackPath;
    private final String oauthTokenUrl;
    private final String oauthClientId;
    private final String oauthClientSecret;
    private final String oauthDefaultProject;
    private final String oauthClaimIdAttribute;
    @Inject
    public ALBCognitoOAuth2CookieFilter(PropertiesProvider propertiesProvider, UsersWritable users, SessionIdStore sessionIdStore) {
        super(propertiesProvider, users, sessionIdStore);
        this.oauthAuthorizeUrl = propertiesProvider.get("oauthAuthorizeUrl").orElse("http://localhost");
        this.oauthTokenUrl = propertiesProvider.get("oauthTokenUrl").orElse("http://localhost");
        this.oauthApiUrl = propertiesProvider.get("oauthApiUrl").orElse("http://localhost");
        this.oauthClientId = propertiesProvider.get("oauthClientId").orElse("");
        this.oauthClientSecret = propertiesProvider.get("oauthClientSecret").orElse("");
        this.oauthDefaultProject = propertiesProvider.get("oauthDefaultProject").orElse("");
        this.oauthCallbackPath = propertiesProvider.get("oauthCallbackPath").orElse("/auth/callback");

        // The attribute to be used as the user ID. Since this is coming from Cognito, which will
        // always have the username claim, we can safely default to "username".
        // This can be overridden by setting the "oauthClaimIdAttribute" property when bootstrapping Datashare.
        this.oauthClaimIdAttribute = propertiesProvider.get("oauthClaimIdAttribute").orElse("username");
        this.defaultOauthApi = new DefaultApi20() {
            @Override public String getAccessTokenEndpoint() { return oauthTokenUrl;}
            @Override protected String getAuthorizationBaseUrl() { return oauthAuthorizeUrl;}
        };
    }

    @Override
    protected Payload callback(Context context) throws IOException, ExecutionException, InterruptedException {
        logger.info("callback called with {}={} {}={}", REQUEST_CODE_KEY, context.get(REQUEST_CODE_KEY), REQUEST_STATE_KEY, context.get(REQUEST_STATE_KEY));
        if (context.get(REQUEST_CODE_KEY) == null || context.get(REQUEST_STATE_KEY) == null || !"GET".equals(context.method()) ||
                sessionIdStore.getLogin(context.get(REQUEST_STATE_KEY)) == null) {
            return Payload.badRequest();
        }
        OAuth20Service service = new ServiceBuilder(oauthClientId).apiSecret(oauthClientSecret).
                callback(getCallbackUrl(context)).
                build(defaultOauthApi);

        logger.info("getting an access token from {} and code value", service);
        OAuth2AccessToken accessToken = service.getAccessToken(context.get(REQUEST_CODE_KEY));

        final OAuthRequest request = new OAuthRequest(Verb.GET, oauthApiUrl);
        service.signRequest(accessToken, request);
        logger.info("sending request to user API signed with the token : {}", request);
        final Response oauthApiResponse = service.execute(request);

        logger.info("Received response body from user API: {}", oauthApiResponse.getBody());
        String jsonBody = oauthApiResponse.getBody();
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode root = (ObjectNode) mapper.readTree(jsonBody);

        // Amend root with user ID in all cases
        // Assuming oauthClaimIdAttribute points to a valid field in root
        // Check if the attribute exists to avoid NullPointerException
        if (root.has(oauthClaimIdAttribute)) {
            root.put("id", root.get(oauthClaimIdAttribute).asText());
        } else {
            // Handle the case where the attribute doesn't exist.
            logger.error("The attribute {} does not exist in the response body.", oauthClaimIdAttribute);
            return Payload.badRequest();
        }

        // Common logic to set 'groups_by_applications' if 'oauthDefaultProject' is not empty
        if (!oauthDefaultProject.isEmpty()) {
            ArrayNode arrayNode = mapper.createArrayNode();
            arrayNode.add(oauthDefaultProject);
            ObjectNode objectNode = mapper.createObjectNode();
            objectNode.set("datashare", arrayNode);
            root.put("groups_by_applications", objectNode);
            logger.info("Modified user with 'groups_by_applications': {}", root);
        }

        // Creating DatashareUser and performing saveOrUpdate in all cases
        org.icij.datashare.user.User user = fromJson(mapper.writeValueAsString(root), "icij");
        DatashareUser datashareUser = new DatashareUser(user.details);
        writableUsers().saveOrUpdate(datashareUser);
        return Payload.seeOther(this.validRedirectUrl(this.readRedirectUrlInCookie(context)))
                .withCookie(this.authCookie(this.buildCookie(datashareUser, "/")));

    }

    private String getCallbackUrl(Context context) {
        String host = ofNullable(context.request().header("x-forwarded-host")).orElse(context.request().header("Host"));
        String proto = ofNullable(context.request().header("x-forwarded-proto")).orElse(context.request().isSecure() ? "https" : "http");
        String url = proto + "://" + host + this.oauthCallbackPath;
        logger.info("oauth callback url = {}", url);
        return url;
    }

    private UsersWritable writableUsers() { return (UsersWritable) users;}
}
