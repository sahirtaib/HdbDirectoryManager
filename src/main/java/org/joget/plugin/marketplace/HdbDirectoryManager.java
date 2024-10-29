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

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import org.json.JSONObject;

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
        String loginUrl = "https://t5146.free.beeceptor.com/api/Account/Authenticate";
        String username = request.getParameter("hdbUsername");
        String password = request.getParameter("hdbPassword");

        try{
            URL url = new URL(loginUrl);
            HttpURLConnection hdb = (HttpURLConnection) url.openConnection();
            hdb.setRequestMethod("POST");
            hdb.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            hdb.setDoOutput(true);

            String params = "userName=" + username + "&password=" + password;

            try (OutputStream os = hdb.getOutputStream()) {
                os.write(params.getBytes());
                os.flush();
            }

            if (hdb.getResponseCode() == HttpURLConnection.HTTP_OK) {
                // read response body
                BufferedReader in = new BufferedReader(new InputStreamReader(hdb.getInputStream()));
                String inputLine;
                StringBuilder responseBuiler = new StringBuilder();

                while ((inputLine = in.readLine()) != null) {
                    responseBuiler.append(inputLine);
                }

                in.close();

                // Parse the JSON response
                JSONObject payload = new JSONObject(responseBuiler.toString());

                doLogin(username, password, payload);

                SavedRequest savedRequest = new HttpSessionRequestCache().getRequest(request, response);
                String savedUrl = savedRequest.getRedirectUrl().isEmpty() ? request.getContextPath() : savedRequest.getRedirectUrl();

                response.sendRedirect(savedUrl);
            }
            else {
                LogUtil.error(getClassName(), null, hdb.getResponseMessage());
                response.sendRedirect(request.getContextPath() + "/web/login?login_error=1");
            }
        } catch (IOException ex) {
            LogUtil.error(getClassName(), ex, ex.getMessage());
        }

    }

    void doLogin(String username, String password, JSONObject payload) {
        User user = new User();
        user.setId(username);
        user.setUsername(username);
        user.setPassword(password);
        user.setTimeZone("0");
        user.setActive(1);
        user.setEmail(payload.getString("EmailID"));
        user.setFirstName(payload.getString("FirstName"));
        user.setLastName(payload.getString("LastName"));

        // set role
        RoleDao roleDao = (RoleDao) AppUtil.getApplicationContext().getBean("roleDao");
        Set roleSet = new HashSet();
        Role r = roleDao.getRole("ROLE_USER");
        if (r != null) {
            roleSet.add(r);
        }
        user.setRoles(roleSet);

        /**
         * need to see whats userDao.addUser(user) is doing
         */
        // add user
        // UserDao userDao = (UserDao) AppUtil.getApplicationContext().getBean("userDao");
        // userDao.addUser(user);

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

        // add audit trail
        WorkflowHelper workflowHelper = (WorkflowHelper) AppUtil.getApplicationContext().getBean("workflowHelper");
        workflowHelper.addAuditTrail(getClassName(), "authenticate", "Authentication for user " + username + ": " + true);
    }
}
