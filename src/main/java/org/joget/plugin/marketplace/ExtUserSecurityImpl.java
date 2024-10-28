package org.joget.plugin.marketplace;

import java.util.Map;
import org.joget.apps.app.service.AppUtil;
import org.joget.commons.util.ResourceBundleUtil;
import org.joget.directory.model.service.DirectoryManagerProxyImpl;
import org.joget.directory.model.service.UserSecurity;
import org.joget.plugin.base.HiddenPlugin;
import org.joget.plugin.base.PluginManager;
import org.joget.plugin.directory.SecureDirectoryManagerImpl;
import org.joget.plugin.directory.UserSecurityImpl;

public class ExtUserSecurityImpl extends UserSecurityImpl implements HiddenPlugin {

    public ExtUserSecurityImpl() {
        super();
    }
    
    @Override
    public String getName() {
        return "HDB User Security";
    }

    @Override
    public String getDescription() {
        return "User Security for HDB";
    }

    @Override
    public String getVersion() {
        return Activator.VERSION;
    }
    
    @Override
    public String getLabel() {
        return "HDB User Security";
    }

    /**
     * Override login form footer to insert HDB login button
     */
    @Override
    public String getLoginFormFooter() {
        String content = "";

        for (UserSecurity us : getSubUserSecurityImpls()) {
            content += us.getLoginFormFooter();
        }

        return content + String.join("",
            "<button id=\"hdbLogin\" class=\"btn btn-info btn-block\">",
                "HDB Login",
            "</button>",
            "<script>",
            "$(document).ready(function(){",
                "$('#hdbLogin').click(() => {",
                    "var form = $('#loginForm');",
                    "$('#j_username', form).attr('name', 'hdbUsername');",
                    "$('#j_password', form).attr('name', 'hdbPassword');",
                    "form.attr('action', '/jw/web/json/plugin/org.joget.plugin.marketplace.HdbDirectoryManager/service')",
                    ".submit()",
                "})",
            "})",
            "</script>"
        );
    }

    /**
     * Override this method so that the templates will be read from the main
     * non-OSGI classloader
     *
     * @param template
     * @param model
     * @return
     */
    @Override
    protected String getTemplate(String template, Map model) {
        PluginManager pluginManager = (PluginManager) AppUtil.getApplicationContext().getBean("pluginManager");
        String content = pluginManager.getPluginFreeMarkerTemplate(model, UserSecurityImpl.class.getName(), "/templates/" + template + ".ftl", null);
        return content;
    }
}
