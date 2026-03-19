package com.ciq.fuzzball

import com.ciq.fuzzball.api.ApiConfig
import groovy.json.JsonSlurper
import groovy.util.logging.Slf4j
import okhttp3.Authenticator
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.Route

/**
 * OkHttp Authenticator that handles Fuzzball API token expiry by performing a two-hop refresh:
 *
 *   1. Exchange the current Keycloak offline refresh token for a new Keycloak access token
 *      (and a rotated refresh token — Keycloak invalidates the old one on use).
 *   2. Exchange the Keycloak access token for a new Fuzzball API token.
 *
 * The refresher is only active when FUZZBALL_REFRESH_TOKEN is set in the environment,
 * which the nf-fuzzball-submit setup job arranges for direct-login and device-login flows.
 * Config-file-based flows use a long-lived static token and do not set this variable.
 */
@Slf4j
class FuzzballTokenRefresher implements Authenticator {

    private final ApiConfig config
    private final OkHttpClient refreshClient
    private volatile String currentRefreshToken

    FuzzballTokenRefresher(ApiConfig config, String initialRefreshToken, OkHttpClient refreshClient) {
        this.config = config
        this.currentRefreshToken = initialRefreshToken
        this.refreshClient = refreshClient
    }

    /**
     * Called by OkHttp when a response is 401. Synchronized to prevent concurrent refresh races:
     * if two threads both get a 401 simultaneously, the second to acquire the lock will see that
     * the token has already been updated and will simply retry with the new token.
     */
    @Override
    synchronized Request authenticate(Route route, Response response) {
        if (!currentRefreshToken) {
            log.warn('No refresh token available, cannot renew Fuzzball API token')
            return null
        }

        // Another thread already refreshed while we were waiting for the lock.
        String responseToken = response.request().header('Authorization')?.replace('Bearer ', '')
        if (config.token != responseToken) {
            return response.request().newBuilder()
                .header('Authorization', "Bearer ${config.token}")
                .build()
        }

        // Guard against infinite retry loops (OkHttp default is also 3, but be explicit).
        if (responseCount(response) > 1) {
            log.error('Token refresh already attempted for this request, giving up')
            return null
        }

        log.info('Fuzzball API token expired, refreshing via Keycloak...')
        try {
            def (String newAccessToken, String newRefreshToken) = exchangeWithKeycloak(currentRefreshToken)
            String newApiToken = getFuzzballApiToken(newAccessToken)
            config.token = newApiToken
            currentRefreshToken = newRefreshToken
            log.info('Token refresh successful')
            return response.request().newBuilder()
                .header('Authorization', "Bearer ${newApiToken}")
                .build()
        } catch (Exception e) {
            log.error("Token refresh failed: ${e.message}", e)
            return null
        }
    }

    /**
     * Exchange the current offline refresh token with Keycloak.
     * Returns [newAccessToken, newRefreshToken] — Keycloak rotates the refresh token on every use.
     */
    private List<String> exchangeWithKeycloak(String refreshToken) {
        String tokenUrl = "${config.oidcServerURL.replaceAll('/+$', '')}/protocol/openid-connect/token"
        FormBody body = new FormBody.Builder()
            .add('client_id', 'fuzzball-cli')
            .add('grant_type', 'refresh_token')
            .add('refresh_token', refreshToken)
            .build()
        Request request = new Request.Builder()
            .url(tokenUrl)
            .post(body)
            .build()
        refreshClient.newCall(request).execute().withCloseable { Response resp ->
            String respBody = resp.body()?.string()
            if (!resp.successful) {
                throw new IOException("Keycloak token exchange failed: HTTP ${resp.code()}")
            }
            if (!respBody) {
                throw new IOException('Empty response body from Keycloak token endpoint')
            }
            def json = new JsonSlurper().parseText(respBody) as Map
            if (!json.access_token) {
                throw new IOException('No access_token in Keycloak response')
            }
            if (!json.refresh_token) {
                throw new IOException('No refresh_token in Keycloak response — is token rotation enabled?')
            }
            return [json.access_token as String, json.refresh_token as String]
        }
    }

    /**
     * Exchange a Keycloak access token for a Fuzzball API token.
     */
    private String getFuzzballApiToken(String accessToken) {
        String url = "${config.schema}://${config.host}:${config.port}" +
                     "${config.basePath}/accounts/${config.accountId}/token"
        Request request = new Request.Builder()
            .url(url)
            .get()
            .header('Authorization', "Bearer ${accessToken}")
            .header('Accept', 'application/json')
            .build()
        refreshClient.newCall(request).execute().withCloseable { Response resp ->
            String respBody = resp.body()?.string()
            if (!resp.successful) {
                throw new IOException("Fuzzball token exchange failed: HTTP ${resp.code()}")
            }
            if (!respBody) {
                throw new IOException('Empty response body from Fuzzball token endpoint')
            }
            def json = new JsonSlurper().parseText(respBody) as Map
            if (!json.token) {
                throw new IOException('No token in Fuzzball API response')
            }
            return json.token as String
        }
    }

    private static int responseCount(Response response) {
        int count = 1
        Response prior = response
        while ((prior = prior.priorResponse()) != null) {
            count++
        }
        return count
    }

}
