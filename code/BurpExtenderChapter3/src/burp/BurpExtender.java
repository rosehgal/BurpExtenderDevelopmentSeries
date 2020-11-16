package burp;

public class BurpExtender implements IBurpExtender{
    @Override public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("Proxy Request Logger");
        callbacks.issueAlert("Extension loaded");

        /*
            Register our LogProxyRequest instance to burp suite proxy.
         */
        callbacks.registerHttpListener(new LogProxyRequests(callbacks));
    }
}
