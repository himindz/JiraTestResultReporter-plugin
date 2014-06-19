package JiraTestResultReporter;

import hudson.Launcher;
import hudson.Extension;
import hudson.FilePath;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.model.AbstractProject;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.BuildStepMonitor;
import hudson.tasks.Notifier;
import hudson.tasks.Publisher;
import hudson.tasks.junit.CaseResult;
import hudson.tasks.test.AbstractTestResultAction;
import hudson.util.FormValidation;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;

import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScheme;
import org.apache.http.auth.AuthState;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.ClientContext;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.AbstractHttpClient;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpProtocolParams;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.ExecutionContext;
import org.apache.http.protocol.HttpContext;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Date;
import java.util.List;

public class JiraReporter extends Notifier {

	public String projectKey;
	public String serverAddress;
	public String username;
	public String password;

	public boolean debugFlag;
	public boolean verboseDebugFlag;
	public boolean createAllFlag;

	private FilePath workspace;

	private static final int JIRA_SUCCESS_CODE = 201;

	private static final String PluginName = new String(
			"[JiraTestResultReporter]");
	private final String pInfo = String.format("%s [INFO]", PluginName);
	private final String pDebug = String.format("%s [DEBUG]", PluginName);

	private final String prefixError = String.format("%s [ERROR]", PluginName);

	private BasicHttpContext localContext;

	@DataBoundConstructor
	public JiraReporter(String projectKey, String serverAddress,
			String username, String password, boolean createAllFlag,
			boolean debugFlag, boolean verboseDebugFlag) {
		if (serverAddress.endsWith("/")) {
			this.serverAddress = serverAddress;
		} else {
			this.serverAddress = serverAddress + "/";
		}

		this.projectKey = projectKey;
		this.username = username;
		this.password = password;

		this.verboseDebugFlag = verboseDebugFlag;
		if (verboseDebugFlag) {
			this.debugFlag = true;
		} else {
			this.debugFlag = debugFlag;
		}

		this.createAllFlag = createAllFlag;
	}

	@Override
	public BuildStepMonitor getRequiredMonitorService() {
		return BuildStepMonitor.NONE;
	}

	@Override
	public boolean perform(final AbstractBuild build, final Launcher launcher,
			final BuildListener listener) {
		PrintStream logger = listener.getLogger();
		logger.printf("%s Examining test results...%n", pInfo);
		debugLog(listener, String.format("Build result is %s%n", build
				.getResult().toString()));
		this.workspace = build.getWorkspace();
		debugLog(
				listener,
				String.format("%s Workspace is %s%n", pInfo,
						this.workspace.toString()));
		// if (build.getResult() == Result.UNSTABLE) {
		AbstractTestResultAction<?> testResultAction = build
				.getTestResultAction();
		debugLog(listener, "TEST ResultAction=" + testResultAction);
		List<CaseResult> failedTests = testResultAction.getFailedTests();
		printResultItems(failedTests, listener);
		debugLog(listener, "Calling FindJiraIssues");
		createOrUpdateJiraIssue(failedTests, listener);

		logger.printf("%s Done.%n", pInfo);
		return true;
	}

	private void printResultItems(final List<CaseResult> failedTests,
			final BuildListener listener) {
		if (!this.debugFlag) {
			return;
		}
		PrintStream out = listener.getLogger();
		for (CaseResult result : failedTests) {
			out.printf("%s projectKey: %s%n", pDebug, this.projectKey);
			out.printf("%s errorDetails: %s%n", pDebug,
					result.getErrorDetails());
			out.printf("%s fullName: %s%n", pDebug, result.getFullName());
			out.printf("%s simpleName: %s%n", pDebug, result.getSimpleName());
			out.printf("%s title: %s%n", pDebug, result.getTitle());
			out.printf("%s packageName: %s%n", pDebug, result.getPackageName());
			out.printf("%s name: %s%n", pDebug, result.getName());
			out.printf("%s className: %s%n", pDebug, result.getClassName());
			out.printf("%s failedSince: %d%n", pDebug, result.getFailedSince());
			out.printf("%s status: %s%n", pDebug, result.getStatus().toString());
			out.printf("%s age: %s%n", pDebug, result.getAge());
			out.printf("%s ErrorStackTrace: %s%n", pDebug,
					result.getErrorStackTrace());

			String affectedFile = result.getErrorStackTrace().replace(
					this.workspace.toString(), "");
			out.printf("%s affectedFile: %s%n", pDebug, affectedFile);
			out.printf("%s ----------------------------%n", pDebug);
		}
	}

	void debugLog(final BuildListener listener, final String message) {
		if (!this.debugFlag) {
			return;
		}
		PrintStream logger = listener.getLogger();
		logger.printf("%s %s%n", pDebug, message);
	}

	private DefaultHttpClient createHttpClient(String userName,
			String password, int timeout, BuildListener listener) {
		BasicHttpParams params = new BasicHttpParams();
		int timeoutMilliSeconds = timeout * 1000;
		HttpConnectionParams.setConnectionTimeout(params, timeoutMilliSeconds);
		HttpConnectionParams.setSoTimeout(params, timeoutMilliSeconds);
		DefaultHttpClient client = new DefaultHttpClient(params);

		if (userName != null && !"".equals(userName)) {
			client.getCredentialsProvider().setCredentials(
					new AuthScope(AuthScope.ANY_HOST, AuthScope.ANY_PORT),
					new UsernamePasswordCredentials(userName, password));
			localContext = new BasicHttpContext();
			// Generate BASIC scheme object and stick it to the local execution
			// context
			BasicScheme basicAuth = new BasicScheme();
			localContext.setAttribute("preemptive-auth", basicAuth);
			// Add as the first request interceptor
			client.addRequestInterceptor(new PreemptiveAuth(listener), 0);

		}

		// set the following user agent with each request
		String userAgent = "jirahttp/1.0";
		HttpProtocolParams.setUserAgent(client.getParams(), userAgent);
		return client;
	}

	String findJiraIssues(String name, final BuildListener listener) {
		String id = null;
		try {
			String url = this.serverAddress + "rest/api/2/search?jql=reporter="
					+ this.username;
			debugLog(listener, "Finding JIRA Issue: " + name);
			String result = getJiraResponse(url, listener);
			JSONObject json = (JSONObject) JSONSerializer.toJSON(result);
			if (json.containsKey("issues")) {
				JSONArray issues = json.getJSONArray("issues");
				for (int i = 0; i < issues.size(); i++) {
					JSONObject issue = (JSONObject) issues.get(i);
					if (issue.containsKey("fields")) {
						JSONObject fields = issue.getJSONObject("fields");
						if (fields.containsKey("summary")) {
							String summary = fields.getString("summary");
							if (summary.startsWith(name)) {
								id = issue.getString("key");
							}
						}
					} else {
						debugLog(listener, "Fields not found in ISSUE " + issue);
					}
				}
			} else {
				debugLog(listener, "ISSUES key not found in " + json);
			}

		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		debugLog(listener, " Issue Found:" + id);
		return id;
	}

	void createJiraIssue(CaseResult result, BuildListener listener) {
		String url = this.serverAddress + "rest/api/2/issue/";

		debugLog(listener, String.format(
				"Creating issue in project %s at URL %s%n", this.projectKey,
				url));
		String stacktrace = result.getErrorStackTrace()
				.replace(this.workspace.toString(), "").replace("\n", " ");
		String jsonPayLoad = new String(
				"{\"fields\": {\"project\": {\"key\": \"" + this.projectKey
						+ "\"},\"summary\": \"" + result.getName()
						+ " failed. " + "\",\"description\": \"" + stacktrace
						+ "\",\"issuetype\": {\"name\": \"Bug\"}}}");

		postJira(url, jsonPayLoad, listener);
	}

	void updateJiraIssue(String issue_id, String comment, BuildListener listener) {
		debugLog(listener, "Updating Issue : " + issue_id);
		String url = this.serverAddress + "rest/api/2/issue/" + issue_id
				+ "/comment";

		debugLog(listener, String.format(
				"Updating issue in project %s at URL %s%n", this.projectKey,
				url));
		String jsonPayLoad = new String("{\"body\": \"" + comment + "\"}");
		postJira(url, jsonPayLoad, listener);
	}

	String postJira(String url, String jsonPayLoad, BuildListener listener) {
		StringBuffer result = new StringBuffer();

		try {
			DefaultHttpClient httpClient = new DefaultHttpClient();
			Credentials creds = new UsernamePasswordCredentials(this.username,
					this.password);
			((AbstractHttpClient) httpClient).getCredentialsProvider()
					.setCredentials(AuthScope.ANY, creds);
			HttpPost postRequest = new HttpPost(url);
			StringEntity params = new StringEntity(jsonPayLoad);
			params.setContentType("application/json");
			postRequest.setEntity(params);
			try {
				postRequest.addHeader(new BasicScheme().authenticate(
						new UsernamePasswordCredentials(this.username,
								this.password), postRequest));
			} catch (AuthenticationException a) {
				a.printStackTrace();
			}
			HttpResponse response = httpClient.execute(postRequest);
			debugLog(listener, " Status Code="
					+ response.getStatusLine().getStatusCode());
			if (response.getStatusLine().getStatusCode() != JIRA_SUCCESS_CODE
					&& response.getStatusLine().getStatusCode() != 204) {
				InputStream is = response.getEntity().getContent();
				if (is != null) {
					BufferedReader rd = new BufferedReader(
							new InputStreamReader(is));
					String line = "";
					while ((line = rd.readLine()) != null) {
						result.append(line);
					}
				}
				throw new RuntimeException(this.prefixError
						+ " Failed : HTTP error code : "
						+ response.getStatusLine().getStatusCode());
			}

			httpClient.getConnectionManager().shutdown();
		} catch (MalformedURLException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return result.toString();
	}

	String getJiraResponse(String url, BuildListener listener) {
		StringBuffer result = new StringBuffer();
		try {
			DefaultHttpClient httpClient = createHttpClient(this.username,
					this.password, 30, listener);
			HttpGet getRequest = new HttpGet(url);
			HttpResponse response = httpClient
					.execute(getRequest, localContext);
			BufferedReader rd;
			rd = new BufferedReader(new InputStreamReader(response.getEntity()
					.getContent()));
			String line = "";
			while ((line = rd.readLine()) != null) {
				result.append(line);
			}

			httpClient.getConnectionManager().shutdown();

		} catch (MalformedURLException e1) {
			e1.printStackTrace();
		} catch (IllegalStateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return result.toString();
	}

	String getJiraTransitions(String issue_id, BuildListener listener) {
		debugLog(listener, "Updating Issue : " + issue_id);
		String url = this.serverAddress + "rest/api/2/issue/" + issue_id
				+ "/transitions";
		String result = getJiraResponse(url, listener);
		debugLog(listener, result);
		return result;
	}

	String getReopenTransitionId(String issue_id, BuildListener listener) {
		String response = getJiraTransitions(issue_id, listener);
		JSONObject json = (JSONObject) JSONSerializer.toJSON(response);
		if (json.containsKey("transitions")) {
			JSONArray transitions = json.getJSONArray("transitions");
			for (int i = 0; i < transitions.size(); i++) {
				JSONObject transition = (JSONObject) transitions.get(i);
				if (transition.containsKey("name")) {
					String name = transition.getString("name").toLowerCase();
					if (name.equals("reopen") || name.equals("reopen issue")) {
						return transition.getString("id");
					}
				}
			}
		}
		return null;
	}

	boolean reOpenJiraIssue(String issue_id, BuildListener listener) {
		String transition_id = getReopenTransitionId(issue_id, listener);
		if (transition_id != null) {
			String url = this.serverAddress + "rest/api/2/issue/" + issue_id
					+ "/transitions";
			debugLog(listener, String.format(
					"Reopening issue in project %s at URL %s%n",
					this.projectKey, url));
			String jsonPayLoad = new String(
					"{\"update\": {\"comment\": [{\"add\": {\"body\": \"Reopened after failure in automated test.\"}}]},\"transition\": {\"id\": \""
							+ transition_id + "\"}}");
			debugLog(listener, "Transiton : " + jsonPayLoad);
			postJira(url, jsonPayLoad, listener);
			return true;
		}
		return false;

	}

	void createOrUpdateJiraIssue(final List<CaseResult> failedTests,
			final BuildListener listener) {
		PrintStream logger = listener.getLogger();

		for (CaseResult result : failedTests) {
			if ((result.getAge() == 1) || (this.createAllFlag)) {
				String existing_issue_id = findJiraIssues(result.getName(),
						listener);
				if (existing_issue_id == null) {
					createJiraIssue(result, listener);
				} else {
					String comment = "Failed on "+new Date();
					if (reOpenJiraIssue(existing_issue_id, listener)){
						comment = "Reopened after failure on "+new Date();
					}
					updateJiraIssue(existing_issue_id,comment, listener);

				}

			} else {
				logger.printf("%s This issue is old; not reporting.%n", pInfo);
			}
		}
	}

	@Override
	public DescriptorImpl getDescriptor() {
		return (DescriptorImpl) super.getDescriptor();
	}

	@Extension
	public static final class DescriptorImpl extends
			BuildStepDescriptor<Publisher> {

		@Override
		public boolean isApplicable(
				final Class<? extends AbstractProject> jobType) {
			return true;
		}

		@Override
		public String getDisplayName() {
			return "Jira Test Result Reporter";
		}

		public FormValidation doCheckProjectKey(@QueryParameter String value) {
			if (value.isEmpty()) {
				return FormValidation.error("You must provide a project key.");
			} else {
				return FormValidation.ok();
			}
		}

		public FormValidation doCheckServerAddress(@QueryParameter String value) {
			if (value.isEmpty()) {
				return FormValidation.error("You must provide an URL.");
			}

			try {
				new URL(value);
			} catch (final MalformedURLException e) {
				return FormValidation.error("This is not a valid URL.");
			}

			return FormValidation.ok();
		}
	}

	static class PreemptiveAuth implements HttpRequestInterceptor {
		BuildListener listener;

		public PreemptiveAuth(BuildListener listener) {
			this.listener = listener;
		}

		public void process(final HttpRequest request, final HttpContext context)
				throws HttpException, IOException {
			AuthState authState = (AuthState) context
					.getAttribute(ClientContext.TARGET_AUTH_STATE);
			// If no auth scheme available yet, try to initialize it
			// preemptively
			if (authState.getAuthScheme() == null) {
				AuthScheme authScheme = (AuthScheme) context
						.getAttribute("preemptive-auth");
				CredentialsProvider credsProvider = (CredentialsProvider) context
						.getAttribute(ClientContext.CREDS_PROVIDER);
				HttpHost targetHost = (HttpHost) context
						.getAttribute(ExecutionContext.HTTP_TARGET_HOST);

				if (authScheme != null) {
					Credentials creds = credsProvider
							.getCredentials(new AuthScope(targetHost
									.getHostName(), targetHost.getPort()));
					if (creds == null) {
						throw new HttpException(
								"No credentials for preemptive authentication");
					}
					authState.setAuthScheme(authScheme);
					authState.setCredentials(creds);

				}
			}
		}
	}
}
