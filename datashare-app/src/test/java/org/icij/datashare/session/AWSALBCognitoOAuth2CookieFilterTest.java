package org.icij.datashare.session;

import net.codestory.http.WebServer;
import net.codestory.http.misc.Env;
import net.codestory.http.security.SessionIdStore;
import net.codestory.rest.FluentRestTest;
import org.icij.datashare.PropertiesProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.mock;

public class AWSALBCognitoOAuth2CookieFilterTest implements FluentRestTest {
    private static WebServer webServer = new WebServer() {
        @Override
        protected Env createEnv() { return Env.prod();}
    }.startOnRandomPort();;
    private static ALBCognitoOAuth2CookieFilter awsAlbCognitoOAuth2CookieFilter;
    static PropertiesProvider propertiesProvider = new PropertiesProvider(new HashMap<>() {{
        put("messageBusAddress", "redis");
        put("oauthTokenUrl", "http://localhost:" + webServer.port() + "/oauth/token");
        put("oauthAuthorizeUrl", "http://localhost:" + webServer.port() + "/oauth/authorize");
        put("oauthApiUrl", "http://localhost:" + webServer.port() + "/api/v1/me.json");
        put("oauthSigninPath", "/auth/signin");
        put("oauthClientId", "12345");
        put("oauthClientSecret", "abcdef");
        put("oauthCallbackPath", "/auth/callback");
    }});

    @BeforeClass
    public static void startServer() {
        webServer = new WebServer().configure(routes -> {
            // Mocking AWS Cognito /oauth2/userInfo endpoint with user info response
            routes.get("/oauth2/userInfo", context -> {
                Map<String, Object> userInfo = new HashMap<>();
                userInfo.put("sub", "pseudorandom");
                userInfo.put("email_verified", true);
                userInfo.put("email", "john.doe@example.com");
                userInfo.put("preferred_username", "john.doe");
                userInfo.put("username", "john.doe");
                return userInfo;
            });

            // Setup AWSALBCognitoOAuth2CookieFilter with mock properties
            UsersWritable users = new UsersInRedis(propertiesProvider);
            SessionIdStore sessionIdStore = new RedisSessionIdStore(propertiesProvider);
            awsAlbCognitoOAuth2CookieFilter = new ALBCognitoOAuth2CookieFilter(propertiesProvider, users, sessionIdStore);

            // Integrate AWSALBCognitoOAuth2CookieFilter into the server's route
            routes.filter(awsAlbCognitoOAuth2CookieFilter);
        }).startOnRandomPort();
    }

    @Test
    public void testOAuthCallbackMutatesResponseBody() {
        // TODO: Implement test when the callback method is implemented
    }

    @Override
    public int port() {
        return webServer.port();
    }
}

