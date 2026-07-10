package io.cxray.jenkins;

import com.fasterxml.jackson.databind.ObjectMapper;
import hudson.Extension;
import hudson.util.FormValidation;
import java.io.IOException;
import jenkins.model.GlobalConfiguration;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

/**
 * Global CXRay settings (Manage Jenkins → System): the API base URL used by Method A. This is the
 * only place the API URL can be set — intentionally admin-only, so a job configurer can't redirect
 * the access-key bearer to an arbitrary host.
 */
@Extension
public class CXRayGlobalConfiguration extends GlobalConfiguration {

    private String apiUrl;      // console origin + /api, e.g. https://console.example/api
    private int timeoutSec = 30;
    private String notifyWebhookUrl; // Slack/Teams/generic incoming webhook, posted on gate FAIL
    private String defaultPolicyJson; // org default policy (JSON) merged UNDER each repo's .cxray/policy.json

    public CXRayGlobalConfiguration() {
        load();
    }

    public static CXRayGlobalConfiguration get() {
        return GlobalConfiguration.all().get(CXRayGlobalConfiguration.class);
    }

    public String getApiUrl() {
        return apiUrl;
    }

    @DataBoundSetter
    public void setApiUrl(String apiUrl) {
        this.apiUrl = (apiUrl == null || apiUrl.trim().isEmpty()) ? null : apiUrl.trim().replaceAll("/+$", "");
        save();
    }

    public int getTimeoutSec() {
        return timeoutSec;
    }

    @DataBoundSetter
    public void setTimeoutSec(int timeoutSec) {
        this.timeoutSec = timeoutSec > 0 ? timeoutSec : 30;
        save();
    }

    public String getNotifyWebhookUrl() {
        return notifyWebhookUrl;
    }

    @DataBoundSetter
    public void setNotifyWebhookUrl(String notifyWebhookUrl) {
        this.notifyWebhookUrl = (notifyWebhookUrl == null || notifyWebhookUrl.trim().isEmpty())
                ? null : notifyWebhookUrl.trim();
        save();
    }

    public String getDefaultPolicyJson() {
        return defaultPolicyJson;
    }

    @DataBoundSetter
    public void setDefaultPolicyJson(String defaultPolicyJson) {
        this.defaultPolicyJson = (defaultPolicyJson == null || defaultPolicyJson.trim().isEmpty())
                ? null : defaultPolicyJson.trim();
        save();
    }

    @Override
    public boolean configure(StaplerRequest req, JSONObject json) {
        req.bindJSON(this, json);
        save();
        return true;
    }

    public FormValidation doCheckApiUrl(@QueryParameter String value) {
        if (value == null || value.trim().isEmpty()) return FormValidation.ok();
        String v = value.trim();
        if (!v.matches("^https?://.+")) return FormValidation.error("Must be an http(s) URL ending in /api.");
        if (v.regionMatches(true, 0, "http://", 0, 7)) {
            return FormValidation.warning("Use https:// — the access-key bearer is sent on every request and would travel in cleartext over http.");
        }
        return FormValidation.ok();
    }

    public FormValidation doCheckNotifyWebhookUrl(@QueryParameter String value) {
        if (value == null || value.trim().isEmpty()) return FormValidation.ok();
        if (!value.trim().matches("^https?://.+")) return FormValidation.error("Must be an http(s) webhook URL.");
        return FormValidation.ok();
    }

    public FormValidation doCheckDefaultPolicyJson(@QueryParameter String value) {
        if (value == null || value.trim().isEmpty()) return FormValidation.ok();
        try {
            new ObjectMapper().readTree(value);
            return FormValidation.ok();
        } catch (IOException e) {
            return FormValidation.error("Not valid JSON: " + e.getMessage());
        }
    }
}
