package io.cxray.jenkins;

import hudson.Extension;
import hudson.util.FormValidation;
import jenkins.model.GlobalConfiguration;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

/**
 * Global CXRay settings (Manage Jenkins → System): the API base URL used by Method A. A per-job
 * {@code apiUrl} may override it.
 */
@Extension
public class CXRayGlobalConfiguration extends GlobalConfiguration {

    private String apiUrl;      // console origin + /api, e.g. https://console.example/api
    private int timeoutSec = 30;

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

    @Override
    public boolean configure(StaplerRequest req, JSONObject json) {
        req.bindJSON(this, json);
        save();
        return true;
    }

    public FormValidation doCheckApiUrl(@QueryParameter String value) {
        if (value == null || value.trim().isEmpty()) return FormValidation.ok();
        if (!value.trim().matches("^https?://.+")) return FormValidation.error("Must be an http(s) URL ending in /api.");
        return FormValidation.ok();
    }
}
