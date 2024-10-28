package org.joget.plugin.marketplace;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.joget.apps.app.service.AppUtil;
import org.joget.apps.workflow.security.WorkflowUserDetails;
import org.joget.commons.util.LogUtil;
import org.joget.commons.util.ResourceBundleUtil;
import org.joget.directory.dao.RoleDao;
import org.joget.directory.dao.UserDao;
import org.joget.directory.ext.DirectoryManagerAuthenticatorImpl;
import org.joget.directory.model.Role;
import org.joget.directory.model.User;
import org.joget.directory.model.service.DirectoryManager;
import org.joget.directory.model.service.DirectoryManagerAuthenticator;
import org.joget.directory.model.service.DirectoryManagerProxyImpl;
import org.joget.directory.model.service.UserSecurityFactory;
import org.joget.plugin.base.PluginManager;
import org.joget.plugin.directory.SecureDirectoryManager;
import org.joget.plugin.directory.SecureDirectoryManagerImpl;
import org.joget.workflow.model.dao.WorkflowHelper;
import org.joget.workflow.util.WorkflowUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.net.URI;
import java.net.URLDecoder;
import org.joget.directory.dao.UserMetaDataDao;
import org.joget.directory.model.UserMetaData;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.util.Scanner;

public class HdbDirectoryManager extends SecureDirectoryManager {
    
    public SecureDirectoryManagerImpl dirManager;

    @Override
    public String getName() {
        return "HDB Directory Manager";
    }

    @Override
    public String getDescription() {
        return "Directory Manager for HDB";
    }

    @Override
    public String getVersion() {
        return Activator.VERSION;
    }

    @Override
    public DirectoryManager getDirectoryManagerImpl(Map properties) {
        if (dirManager == null) {
            dirManager = new ExtSecureDirectoryManagerImpl(properties);
        } else {
            dirManager.setProperties(properties);
        }

        return dirManager;
    }

    @Override
    public String getLabel() {
        return "HDB Directory Manager";
    }

    @Override
    public String getClassName() {
        return getClass().getName();
    }

    @Override
    public String getPropertyOptions() {
        return "";
    }

    @Override
    public void webService(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        LogUtil.info(HdbDirectoryManager.class.getName(), "starts");

        String loginUrl = "https://t5146.free.beeceptor.com/api/Account/Authenticate";
        String username = request.getParameter("hdbUsername");
        String password = request.getParameter("hdbPassword");

        LogUtil.info(HdbDirectoryManager.class.getName(), "username: "+ username);
        LogUtil.info(HdbDirectoryManager.class.getName(), "password: "+ password);

        try{
            URL url = new URL(loginUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setDoOutput(true);

            String params = "userName=" + username +
                    "&password=" + password;

            try (OutputStream os = conn.getOutputStream()) {
                os.write(params.getBytes());
                os.flush();
            }

            int responseCode = conn.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                User user = new User();
                user.setId(username);
                user.setUsername(username);
                user.setPassword(password);
                user.setTimeZone("0");
                user.setActive(1);

                UserDetails details = new WorkflowUserDetails(user);

                DirectoryManagerProxyImpl dm = (DirectoryManagerProxyImpl) AppUtil.getApplicationContext().getBean("directoryManager");
                SecureDirectoryManagerImpl dmImpl = (SecureDirectoryManagerImpl) dm.getDirectoryManagerImpl();

                Collection<Role> roles = dm.getUserRoles(username);
                List<GrantedAuthority> gaList = new ArrayList<>();
                if (roles != null && !roles.isEmpty()) {
                    for (Role role : roles) {
                        GrantedAuthority ga = new SimpleGrantedAuthority(role.getId());
                        gaList.add(ga);
                    }
                }

                UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(username, "", gaList);
                result.setDetails(details);
                SecurityContextHolder.getContext().setAuthentication(result);

                SavedRequest savedRequest = new HttpSessionRequestCache().getRequest(request, response);
                String savedUrl = "";
                if (savedRequest != null) {
                    savedUrl = savedRequest.getRedirectUrl();
                } else {
                    savedUrl = request.getContextPath();
                }
                response.sendRedirect(savedUrl);

            } else {
                LogUtil.info("Error: ", conn.getResponseMessage());
            }
        } catch (IOException ex) {
            LogUtil.error(HdbDirectoryManager.class.getName(), ex, ex.getMessage());
        }

        LogUtil.info(HdbDirectoryManager.class.getName(), "ends");

    }
}
