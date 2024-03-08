package org.icij.datashare.session;

import net.codestory.http.WebServer;
import net.codestory.http.misc.Env;
import net.codestory.http.security.SessionIdStore;
import net.codestory.rest.FluentRestTest;
import org.icij.datashare.PropertiesProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import static java.lang.String.valueOf;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ALBCognitoOAuth2CookieFilterTest implements FluentRestTest {
    private static WebServer webServer = new WebServer() {
        @Override
        protected Env createEnv() { return Env.prod();}
    }.startOnRandomPort();;
    private static ALBCognitoOAuth2CookieFilter awsAlbCognitoOAuth2CookieFilter;
    private static SessionIdStore sessionIdStore;
    private static UsersWritable users;
    private static final PropertiesProvider propertiesProvider = new PropertiesProvider(new HashMap<>() {{
        put("redisAddress", "redis://localhost:6379");
        put("messageBusAddress", "redis://localhost:6379");
        put("oauthTokenUrl", "http://localhost:" + webServer.port() + "/oauth/token");
        put("oauthAuthorizeUrl", "http://localhost:" + webServer.port() + "/oauth/authorize");
        put("oauthApiUrl", "http://localhost:" + webServer.port() + "/oauth2/userInfo");
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
            sessionIdStore = mock(SessionIdStore.class);
            users = mock(UsersWritable.class);
            awsAlbCognitoOAuth2CookieFilter = new ALBCognitoOAuth2CookieFilter(propertiesProvider, users, sessionIdStore);

            // Integrate AWSALBCognitoOAuth2CookieFilter into the server's route
            routes.filter(awsAlbCognitoOAuth2CookieFilter);
        }).startOnRandomPort();
    }

    @Test
    public void testOAuthCallbackMutatesResponseBody() {
        String code = "simulatedAuthCode";
        String state = "simulatedState";
        String callbackUrl = "/auth/callback?code=" + code + "&state=" + state;
        // Hit the callback URL to simulate the OAuth2 callback process
        // get(callbackUrl).should().respond(200);
    }

    @Override
    public int port() {
        return webServer.port();
    }
}

