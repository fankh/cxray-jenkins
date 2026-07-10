package io.cxray.jenkins.api;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * CXRay access-key auth: {@code Authorization: Bearer base64url({accessKey,secretKey})} — the
 * exact wire format the API's {@code checkIpAndAccessKey} expects (matches the cxray-gate CLI's
 * {@code accessKeyBearer}). The key is IP-bound, so the Jenkins agent's egress IP must be
 * registered with CXRay once.
 */
public final class Auth {

    private Auth() {}

    public static String bearer(String accessKey, String secretKey) {
        String json = "{\"accessKey\":\"" + esc(accessKey) + "\",\"secretKey\":\"" + esc(secretKey) + "\"}";
        return "Bearer " + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private static String esc(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
